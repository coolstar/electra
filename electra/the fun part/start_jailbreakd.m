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
#include <sys/stat.h>
#import <Foundation/Foundation.h>
#include "utils.h"

int start_jailbreakd(uint64_t kernel_base) {
    unlink("/var/tmp/jailbreakd.pid");
    unlink("/var/log/jailbreakd-stderr.log");
    unlink("/var/log/jailbreakd-stdout.log");
    
    NSData *blob = [NSData dataWithContentsOfFile:[[NSBundle mainBundle] pathForResource:@"jailbreakd" ofType:@"plist"]];
    NSMutableDictionary *job = [NSPropertyListSerialization propertyListWithData:blob options:NSPropertyListMutableContainers format:nil error:nil];

    job[@"EnvironmentVariables"][@"KernelBase"] = [NSString stringWithFormat:@"0x%16llx", kernel_base];
    [job writeToFile:@"/Library/LaunchDaemons/jailbreakd.plist" atomically:YES];
    chmod("/Library/LaunchDaemons/jailbreakd.plist", 0644);
    chown("/Library/LaunchDaemons/jailbreakd.plist", 0, 0);

    pid_t pid = 0;
    
    int rv = run("launchctl load -w /Library/LaunchDaemons/jailbreakd.plist");
    if (rv == -1) {
        return -1;
    }

    int ex = 0;
    waitpid(pid, &ex, 0);
    NSLog(@"The dragon becomes me!");
    NSLog(@"once it is drawn, it cannot be sheathed without causing death");
    return 0;
}
