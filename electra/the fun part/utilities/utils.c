//
//  utils.c
//  electra
//
//  Created by Jamie on 27/01/2018.
//  Copyright © 2018 Electra Team. All rights reserved.
//

#include "utils.h"
#include <stdint.h>
#include <spawn.h>
#include <sys/wait.h>

#define BOOTSTRAP_PREFIX "/bootstrap"

// Thanks @nitotv
// https://ghostbin.com/paste/rmvp5
int run(const char *cmd) {
    pid_t pid;
    int rv;

    char *environ[] = {
        "BOOTSTRAP_PREFIX=/"BOOTSTRAP_PREFIX"",
        "PATH=/"BOOTSTRAP_PREFIX"/usr/local/bin:/"BOOTSTRAP_PREFIX"/usr/sbin:/"BOOTSTRAP_PREFIX"/usr/bin:/"BOOTSTRAP_PREFIX"/sbin:/"BOOTSTRAP_PREFIX"/bin:/bin:/usr/bin:/sbin:/usr/sbin"
    };

    char *argv[] = {"sh", "-c", (char*)cmd, NULL};
    rv = posix_spawn(&pid, "/bootstrap/bin/sh", NULL, NULL, argv, environ);

    if (rv == 0) {
        if (waitpid(pid, &rv, 0) == -1)
            perror("waitpid");
    }

    return rv;
}

