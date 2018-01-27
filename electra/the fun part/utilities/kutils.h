#ifndef kutils_h
#define kutils_h

#include <mach/mach.h>
#include "IOKit.h"

uint64_t task_self_addr(void);
uint64_t ipc_space_kernel(void);
uint64_t find_kernel_base(void);

uint64_t current_thread(void);

mach_port_t fake_host_priv(void);

size_t kread(uint64_t where, void *p, size_t size);
size_t kwrite(uint64_t where, const void *p, size_t size);
uint64_t kalloc(vm_size_t size);
uint64_t kexecute(mach_port_t user_client, uint64_t fake_client, uint64_t addr, uint64_t x0, uint64_t x1, uint64_t x2, uint64_t x3, uint64_t x4, uint64_t x5, uint64_t x6);

#endif /* kutils_h */
