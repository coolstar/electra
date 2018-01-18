//
//  jailbreakd.c
//  async_wake_ios
//
//  Created by CoolStar on 12/25/17.
//  Copyright © 2017 Ian Beer. All rights reserved.
//

#include <stdio.h>
#include <stdlib.h>
#include <mach/mach.h>
#include <mach/error.h>
#include <mach/message.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#import <Foundation/Foundation.h>
#include <spawn.h>
#import "fun_objc.h"

int start_jailbreakd(uint64_t kernel_base) {
    pid_t pid = 0;

    write_jailbreakd_plist(kernel_base);

    int rv = posix_spawn(&pid, "/bootstrap/bin/launchctl", NULL, NULL, (char **)&(const char*[]){ "launchctl", "load", "-w", "/bootstrap/Library/LaunchDaemons/jailbreakd.plist", NULL }, NULL);
    if (rv == -1) {
        return -1;
    }

    int ex = 0;
    waitpid(pid, &ex, 0);
    NSLog(@"once it is drawn, it cannot be sheathed without causing death");
    return 0;
}
