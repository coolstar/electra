#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include "libjailbreak_xpc.h"

int main(int argc, char **argv, char **envp) {
    if (argc < 3){
        printf("Usage: \n");
        printf("jailbreakd_client <pid> <1 | 2 | 6>\n");
        printf("\t1 = entitle+platformize the target PID\n");
        printf("\t2 = entitle+platformize the target PID and subsequently sent SIGCONT\n");
        printf("\t6 = fixup setuid in the target PID\n");
        return 0;
    }
    if (atoi(argv[2]) != 1 && atoi(argv[2]) != 2 && atoi(argv[2]) != 6){
        printf("Usage: \n");
        printf("jailbreakd_client <pid> <1 | 2 | 6>\n");
        printf("\t1 = entitle the target PID\n");
        printf("\t2 = entitle+platformize the target PID and subsequently sent SIGCONT\n");
        printf("\t6 = fixup setuid in the target PID\n");
        return 0;
    }

    jb_connection_t jbc = jb_connect();

    pid_t pid = atoi(argv[1]);
    int arg = atoi(argv[2]);
    int ret = 0;

    if (arg == 1) {
        ret = jb_entitle_now(jbc, pid, 7 | FLAG_WAIT_EXEC);
    } else if (arg == 2) {
        ret = jb_entitle_now(jbc, pid, 15);
    } else if (arg == 6) {
        ret = jb_fix_setuid_now(jbc, pid);
    }

    jb_disconnect(jbc);
    return ret;
}

// vim:ft=objc
