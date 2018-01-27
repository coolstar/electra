#ifndef PAYLOADS_COMMON_H
#define PAYLOADS_COMMON_H

#include <inttypes.h>

int file_exist(const char *filename);

#define JAILBREAKD_COMMAND_ENTITLE_AND_SIGCONT 2
#define JAILBREAKD_COMMAND_ENTITLE_AND_SIGCONT_AFTER_DELAY 4
#define JAILBREAKD_COMMAND_ENTITLE_AND_SIGCONT_FROM_XPCPROXY 5

void calljailbreakd(pid_t PID, uint8_t command);
void closejailbreakfd(void);

#endif  // PAYLOADS_COMMON_H

