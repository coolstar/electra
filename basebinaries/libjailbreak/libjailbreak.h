//
//  libjailbreak.h
//  libjailbreak
//
//  Created by Jamie Bishop on 29/01/2018.
//  Copyright © 2018 Electra Team. All rights reserved.
//

#import <Foundation/Foundation.h>
#include <stdint.h>
#include <sys/types.h>

void jb_entitle(pid_t pid);
void jb_platformize(pid_t pid);
void jb_fix_setuid(pid_t pid);
