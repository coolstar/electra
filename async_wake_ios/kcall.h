#ifndef kcall_h
#define kcall_h

void kprintstr(char* msg);
void test_kcall(void);
//void kcall(uint64_t fptr, uint64_t arg0, uint64_t arg1);
uint64_t kcall(uint64_t fptr, uint32_t argc, ...);
#endif
