#include <stdio.h>
#include <stdlib.h>
#include <sys/sysctl.h>
#include <sys/utsname.h>

#include "symbols.h"
#include "kmem.h"
#include "kutils.h"

// the offsets are unlikely to change between similar models and builds, but the symbol addresses will
// the offsets are required to get the kernel r/w but the symbols aren't

int* offsets = NULL;


/* iOS 11.1.2 */
int kstruct_offsets_15B202[] = {
  0xb,   // KSTRUCT_OFFSET_TASK_LCK_MTX_TYPE,
  0x10,  // KSTRUCT_OFFSET_TASK_REF_COUNT,
  0x14,  // KSTRUCT_OFFSET_TASK_ACTIVE,
  0x20,  // KSTRUCT_OFFSET_TASK_VM_MAP,
  0x28,  // KSTRUCT_OFFSET_TASK_NEXT,
  0x30,  // KSTRUCT_OFFSET_TASK_PREV,
  0x308, // KSTRUCT_OFFSET_TASK_ITK_SPACE
  0x368, // KSTRUCT_OFFSET_TASK_BSD_INFO,
  
  0x0,   // KSTRUCT_OFFSET_IPC_PORT_IO_BITS,
  0x4,   // KSTRUCT_OFFSET_IPC_PORT_IO_REFERENCES,
  0x40,  // KSTRUCT_OFFSET_IPC_PORT_IKMQ_BASE,
  0x50,  // KSTRUCT_OFFSET_IPC_PORT_MSG_COUNT,
  0x60,  // KSTRUCT_OFFSET_IPC_PORT_IP_RECEIVER,
  0x68,  // KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT,
  0x90,  // KSTRUCT_OFFSET_IPC_PORT_IP_CONTEXT,
  0xa0,  // KSTRUCT_OFFSET_IPC_PORT_IP_SRIGHTS,
  
  0x10,  // KSTRUCT_OFFSET_PROC_PID,
  
  0x20,  // KSTRUCT_OFFSET_IPC_SPACE_IS_TABLE
  
  0x180, // KSTRUCT_OFFSET_THREAD_BOUND_PROCESSOR
  0x188, // KSTRUCT_OFFSET_THREAD_LAST_PROCESSOR
  0x190, // KSTRUCT_OFFSET_THREAD_CHOSEN_PROCESSOR
  0x408, // KSTRUCT_OFFSET_THREAD_CONTEXT_DATA
  0x410, // KSTRUCT_OFFSET_THREAD_UPCB
  0x418, // KSTRUCT_OFFSET_THREAD_UNEON
  0x420, // KSTRUCT_OFFSET_THREAD_KSTACKPTR
  
  0x54,  // KSTRUCT_OFFSET_PROCESSOR_CPU_ID
  
  0x28,  // KSTRUCT_OFFSET_CPU_DATA_EXCEPSTACKPTR
  0X78,  // KSTRUCT_OFFSET_CPU_DATA_CPU_PROCESSOR
};

int koffset(enum kstruct_offset offset) {
  if (offsets == NULL) {
    printf("need to call symbols_init() prior to querying offsets\n");
    return 0;
  }
  return offsets[offset];
}

// this is the base of the kernel, not the kernelcache
uint64_t kernel_base = 0;
uint64_t* symbols = NULL;
uint64_t kaslr_slide = 0;

uint64_t ksym(enum ksymbol sym) {
  if (kernel_base == 0) {
    if (!have_kmem_read()) {
      printf("attempted to use symbols prior to gaining kernel read\n");
      return 0;
    }
    kernel_base = find_kernel_base();
    kaslr_slide = find_kernel_base() - 0xFFFFFFF007004000;
  }
  //return symbols[sym] + kernel_base;
  return symbols[sym] + kaslr_slide;
}

int have_syms = 0;
int probably_have_correct_symbols() {
  return have_syms;
}

void offsets_init() {
  size_t size = 32;
  char build_id[size];
  memset(build_id, 0, size);
  int err = sysctlbyname("kern.osversion", build_id, &size, NULL, 0);
  if (err == -1) {
    printf("failed to detect version (sysctlbyname failed\n");
    return;
  }
  printf("build_id: %s\n", build_id);
  
  struct utsname u = {0};
  uname(&u);
  
  printf("sysname: %s\n", u.sysname);
  printf("nodename: %s\n", u.nodename);
  printf("release: %s\n", u.release);
  printf("version: %s\n", u.version);
  printf("machine: %s\n", u.machine);
  
  // set the offsets
  
  if (strcmp(build_id, "15B93") == 0 || strcmp(build_id, "15B150") == 0 || strcmp(build_id, "15B202") == 0) {
    offsets = kstruct_offsets_15B202;
  } else {
    offsets = kstruct_offsets_15B202;
    printf("unknown kernel build. If this is iOS 11 it might still be able to get tfp0, trying anyway\n");
    have_syms = 0;
    return;
  }
}


