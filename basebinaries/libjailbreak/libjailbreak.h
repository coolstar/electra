//
//  libjailbreak.h
//  libjailbreak
//
//  Created by Jamie Bishop on 29/01/2018.
//  Copyright © 2018 Electra Team. All rights reserved.
//

#import <Foundation/Foundation.h>

struct __attribute__((__packed__)) JAILBREAKD_ENTITLE_PID {
    uint8_t Command;
    int32_t Pid;
};

void entitle(void);
void platformize(void);
void fix_setuid(void);
