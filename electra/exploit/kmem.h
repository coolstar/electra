#ifndef kmem_h
#define kmem_h

#include <mach/mach.h>

uint32_t rk32(uint64_t kaddr);
uint64_t rk64(uint64_t kaddr);

void wk32(uint64_t kaddr, uint32_t val);
void wk64(uint64_t kaddr, uint64_t val);

void wkbuffer(uint64_t kaddr, void* buffer, uint32_t length);
void rkbuffer(uint64_t kaddr, void* buffer, uint32_t length);

void kmemcpy(uint64_t dest, uint64_t src, uint32_t length);

void kmem_protect(uint64_t kaddr, uint32_t size, int prot);

uint64_t kmem_alloc(uint64_t size);
uint64_t kmem_alloc_wired(uint64_t size);
void kmem_free(uint64_t kaddr, uint64_t size);

void prepare_rk_via_kmem_read_port(mach_port_t port);
void prepare_rwk_via_tfp0(mach_port_t port);

// query whether kmem read or write is present
int have_kmem_read(void);
int have_kmem_write(void);

#endif
