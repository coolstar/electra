#import "ViewController.h"
#include "async_wake.h"
#include "fun.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <dlfcn.h>

/*
 * Copyright (c) 2006 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 *
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */

#ifndef _SYS_CODESIGN_H_
#define _SYS_CODESIGN_H_

#include <sys/types.h>

/* code signing attributes of a process */
#define    CS_VALID        0x0000001    /* dynamically valid */
#define CS_ADHOC        0x0000002    /* ad hoc signed */
#define CS_GET_TASK_ALLOW    0x0000004    /* has get-task-allow entitlement */
#define CS_INSTALLER        0x0000008    /* has installer entitlement */

#define    CS_HARD            0x0000100    /* don't load invalid pages */
#define    CS_KILL            0x0000200    /* kill process if it becomes invalid */
#define CS_CHECK_EXPIRATION    0x0000400    /* force expiration checking */
#define CS_RESTRICT        0x0000800    /* tell dyld to treat restricted */
#define CS_ENFORCEMENT        0x0001000    /* require enforcement */
#define CS_REQUIRE_LV        0x0002000    /* require library validation */
#define CS_ENTITLEMENTS_VALIDATED    0x0004000

#define    CS_ALLOWED_MACHO    0x00ffffe

#define CS_EXEC_SET_HARD    0x0100000    /* set CS_HARD on any exec'ed process */
#define CS_EXEC_SET_KILL    0x0200000    /* set CS_KILL on any exec'ed process */
#define CS_EXEC_SET_ENFORCEMENT    0x0400000    /* set CS_ENFORCEMENT on any exec'ed process */
#define CS_EXEC_SET_INSTALLER    0x0800000    /* set CS_INSTALLER on any exec'ed process */

#define CS_KILLED        0x1000000    /* was killed by kernel for invalidity */
#define CS_DYLD_PLATFORM    0x2000000    /* dyld used to load this is a platform binary */
#define CS_PLATFORM_BINARY    0x4000000    /* this is a platform binary */
#define CS_PLATFORM_PATH    0x8000000    /* platform binary by the fact of path (osx only) */

/* csops  operations */
#define CS_OPS_STATUS       0   /* return status */
#define CS_OPS_MARKINVALID  1   /* invalidate process */
#define CS_OPS_MARKHARD     2   /* set HARD flag */
#define CS_OPS_MARKKILL     3   /* set KILL flag (sticky) */
#define CS_OPS_PIDPATH      4   /* get executable's pathname */
#define CS_OPS_CDHASH       5   /* get code directory hash */
#define CS_OPS_PIDOFFSET    6   /* get offset of active Mach-o slice */
#define CS_OPS_ENTITLEMENTS_BLOB 7  /* get entitlements blob */
#define CS_OPS_MARKRESTRICT 8   /* set RESTRICT flag (sticky) */

#ifndef KERNEL

__BEGIN_DECLS

/* code sign operations */
int csops(pid_t pid, unsigned int  ops, void * useraddr, size_t usersize);

__END_DECLS

#endif /* ! KERNEL */

#endif /* _SYS_CODESIGN_H_ */

@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
  [super viewDidLoad];
  NSNotificationCenter* notificationCenter = [NSNotificationCenter defaultCenter];
  [notificationCenter addObserver:self selector:@selector(doit:) name:@"Jailbreak" object:nil];
    
    if (kCFCoreFoundationVersionNumber < 1443 || kCFCoreFoundationVersionNumber > 1445.32){
        [jailbreak setEnabled:NO];
        [enableTweaks setEnabled:NO];
        [jailbreak setTitle:@"Version Error" forState:UIControlStateNormal];
    }
    
    uint32_t flags;
    csops(getpid(), CS_OPS_STATUS, &flags, 0);
    
    if ((flags & CS_PLATFORM_BINARY)){
        [jailbreak setEnabled:NO];
        [enableTweaks setEnabled:NO];
        [jailbreak setTitle:@"Already Jailbroken" forState:UIControlStateNormal];
    }
  // Do any additional setup after loading the view, typically from a nib.
}


- (void)didReceiveMemoryWarning {
  printf("******* received memory warning! ***********\n");
  [super didReceiveMemoryWarning];
  // Dispose of any resources that can be recreated.
}

- (IBAction)credits:(id)sender {
    UIAlertController *alertController = [UIAlertController alertControllerWithTitle:@"Credits" message:@"Electra is brought to you by CoolStar, Ian Beer, theninjaprawn, stek29 and xerub.\n\nElectra includes the following software:\namfid patch by theninjaprawn\njailbreakd & tweak injection by CoolStar\nunlocknvram by stek29\nlibsubstitute by comex\nContains code from simject by angelXwind\nAnemone by CoolStar, kirb, isklikas and goeo\nPreferenceLoader by DHowett & rpetrich" preferredStyle:UIAlertControllerStyleAlert];
    [alertController addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
    [self presentViewController:alertController animated:YES completion:nil];
}

- (IBAction)doit:(id)sender {
    [jailbreak setEnabled:NO];
    [enableTweaks setEnabled:NO];
    
    [jailbreak setTitle:@"Please Wait (1/3)" forState:UIControlStateNormal];
    
    BOOL shouldEnableTweaks = [enableTweaks isOn];
    
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0ul), ^{
        mach_port_t user_client;
        mach_port_t tfp0 = get_tfp0(&user_client);
        
        dispatch_async(dispatch_get_main_queue(), ^{
            [jailbreak setTitle:@"Please Wait (2/3)" forState:UIControlStateNormal];
        });
        
        if (let_the_fun_begin(tfp0, user_client, shouldEnableTweaks) == 0){
            dispatch_async(dispatch_get_main_queue(), ^{
                [jailbreak setTitle:@"Jailbroken" forState:UIControlStateNormal];
                
                UIAlertController *dropbearRunning = [UIAlertController alertControllerWithTitle:@"DropBear Running" message:@"DropBear is now running! Enjoy." preferredStyle:UIAlertControllerStyleAlert];
                [dropbearRunning addAction:[UIAlertAction actionWithTitle:@"Exit" style:UIAlertActionStyleCancel handler:^(UIAlertAction * _Nonnull action) {
                    [dropbearRunning dismissViewControllerAnimated:YES completion:nil];
                    exit(0);
                }]];
                [self presentViewController:dropbearRunning animated:YES completion:nil];
            });
        } else {
            dispatch_async(dispatch_get_main_queue(), ^{
                [jailbreak setTitle:@"Error Jailbreaking" forState:UIControlStateNormal];
            });
        }
        
        NSLog(@" ♫ KPP never bothered me anyway... ♫ ");
    });
}

- (UIStatusBarStyle)preferredStatusBarStyle {
    return UIStatusBarStyleLightContent;
}

- (void)dealloc {
    [[NSNotificationCenter defaultCenter] removeObserver:self];
}

@end
