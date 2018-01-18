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

int start_jailbreakd(uint64_t kern_ucred, mach_port_t *pass_port, mach_port_t task_for_pid0, uint64_t kernel_base)
{
    unlink("/var/tmp/jailbreakd.pid");
    pid_t pd;
    
    NSString *kernel_base_str = [NSString stringWithFormat:@"%llu",kernel_base];
    posix_spawn(&pd, "/bootstrap/jailbreakd", NULL, NULL, (char **)&(char*[]){"jailbreakd", (char *)[kernel_base_str UTF8String], NULL}, NULL);
    return 0;
}
