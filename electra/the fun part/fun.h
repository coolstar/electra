//
//  fun.h
//  async_wake_ios
//
//  Created by George on 14/12/17.
//  Copyright © 2017 Ian Beer. All rights reserved.
//

#ifndef fun_h
#define fun_h

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#import <sys/mount.h>
#import <spawn.h>
#import <mach-o/dyld.h>
#import <sys/types.h>
#import <sys/stat.h>
#import <sys/utsname.h>

#include <mach/mach.h>

#include <CoreFoundation/CoreFoundation.h>

#include "find_port.h"
#include "kutils.h"
#include "symbols.h"
#include "patchfinder64.h"

#include "fun_objc.h"

void snapshotWarningRead(void);
int begin_fun(mach_port_t tfp0, mach_port_t user_client, bool enable_tweaks);

int startprog(uint64_t kern_ucred, bool wait, const char *prog, const char* args[], const char* envp[]);
int start_jailbreakd(uint64_t kernel_base);

#endif /* fun_h */
