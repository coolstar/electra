#include <mach/mach.h>
#include <inttypes.h>

extern mach_port_t user_client;
extern uint64_t fake_client;

uint64_t kexecute(mach_port_t user_client, uint64_t fake_client, uint64_t addr, uint64_t x0, uint64_t x1, uint64_t x2, uint64_t x3, uint64_t x4, uint64_t x5, uint64_t x6);
mach_port_t prepare_user_client(void);
