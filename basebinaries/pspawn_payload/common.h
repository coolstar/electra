#ifndef PAYLOADS_COMMON_H
#define PAYLOADS_COMMON_H

#include <inttypes.h>

int file_exist(char *filename);

#define JAILBREAKD_COMMAND_ENTITLE_AND_SIGCONT 2
#define JAILBREAKD_COMMAND_ENTITLE_AND_SIGCONT_AFTER_DELAY 4
#define JAILBREAKD_COMMAND_ROOTIFY 5
#define JAILBREAKD_COMMAND_ROOTIFY_AFTER_DELAY 6

void calljailbreakd(pid_t PID, uint8_t command);

#endif  // PAYLOADS_COMMON_H

