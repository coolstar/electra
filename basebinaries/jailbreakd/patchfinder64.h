#ifndef PATCHFINDER64_H_
#define PATCHFINDER64_H_

#define CACHED_FIND(type, name) \
	type __##name(void);\
	type name(void) { \
		type cached = 0; \
		if (cached == 0) { \
			cached = __##name(); \
		} \
		return cached; \
	} \
	type __##name(void)

int init_kernel(uint64_t base, const char *filename);
void term_kernel(void);

// Fun part
uint64_t find_allproc(void);
uint64_t find_add_x0_x0_0x40_ret(void);
uint64_t find_copyout(void);
uint64_t find_bzero(void);
uint64_t find_bcopy(void);
uint64_t find_rootvnode(void);
uint64_t find_trustcache(void);
uint64_t find_amficache(void);
uint64_t find_OSBoolean_True(void);
uint64_t find_OSBoolean_False(void);

#endif
