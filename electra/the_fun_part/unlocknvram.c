// iOS 11 moves OFVariables to const
// https://twitter.com/s1guza/status/908790514178301952
// however, if we:
//  1) Can find IODTNVRAM service
//  2) Have tfp0 / kernel read|write|alloc
//  3) Can leak kernel address of mach port
// then we can fake vtable on IODTNVRAM object
// async_wake satisfies those requirements
// however, I wasn't able to actually set or get ANY nvram variable
// not even userread/userwrite
// Guess sandboxing won't let to access nvram

#include <stdlib.h>
#include <CoreFoundation/CoreFoundation.h>
#include "kmem.h"
#include "symbols.h"
#include "find_port.h"

// convertPropToObject calls getOFVariableType
// open convertPropToObject, look for first vtable call -- that'd be getOFVariableType
// find xrefs, figure out vtable start from that
// following are offsets of entries in vtable

// it always returns false
const uint64_t searchNVRAMProperty = 0x590;
// 0 corresponds to root only
const uint64_t getOFVariablePerm = 0x558;

typedef mach_port_t io_service_t;
typedef mach_port_t io_connect_t;
extern const mach_port_t kIOMasterPortDefault;
CFMutableDictionaryRef IOServiceMatching(const char *name) CF_RETURNS_RETAINED;
io_service_t IOServiceGetMatchingService(mach_port_t masterPort, CFDictionaryRef matching CF_RELEASES_ARGUMENT);

// get kernel address of IODTNVRAM object
uint64_t get_iodtnvram_obj(void) {
    // get user serv
    io_service_t IODTNVRAMSrv = IOServiceGetMatchingService(kIOMasterPortDefault, IOServiceMatching("IODTNVRAM"));
    
    // leak user serv
    // it should use via_kmem_read method by now, so second param doesn't matter
    uint64_t nvram_up = find_port_address(IODTNVRAMSrv, 0x41414141);
    // get kern obj -- IODTNVRAM*
    uint64_t IODTNVRAMObj = rk64(nvram_up + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT));
    
    return IODTNVRAMObj;
}

void unlocknvram(void) {
    uint64_t obj = get_iodtnvram_obj();
    uint64_t vtable_start = rk64(obj);
    
    uint64_t vtable_end = vtable_start;
    // Is vtable really guaranteed to end with 0 or was it just a coincidence?..
    // should we just use some max value instead?
    while (rk64(vtable_end) != 0) vtable_end += sizeof(uint64_t);
    
    uint32_t vtable_len = (uint32_t) (vtable_end - vtable_start);
    
    // copy vtable to userspace
    uint64_t *buf = calloc(1, vtable_len);
    rkbuffer(vtable_start, buf, vtable_len);
    
    // alter it
    buf[getOFVariablePerm/sizeof(uint64_t)] = buf[searchNVRAMProperty/sizeof(uint64_t)];
    
    // allocate buffer in kernel and copy it back
    uint64_t fake_vtable = kmem_alloc_wired(vtable_len);
    wkbuffer(fake_vtable, buf, vtable_len);
    
    // replace vtable on IODTNVRAM object
    wk64(obj, fake_vtable);
    
    free(buf);
}
