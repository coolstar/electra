//
//  removeElectraBeta.c
//  electra
//
//  Created by CoolStar on 2/12/18.
//  Copyright © 2018 Electra Team. All rights reserved.
//

#include "removeElectraBeta.h"
#include "file_utils.h"
#include <unistd.h>
#include <spawn.h>
#include <sys/wait.h>

void removeElectraBeta(void){
    int rv;
    pid_t pd;
    
    rv = posix_spawn(&pd, "/electra/rm", NULL, NULL, (char **)&(const char*[]){ "rm", "-rf", "/Applications/Anemone.app", NULL }, NULL);
    waitpid(pd, NULL, 0);
    
    rv = posix_spawn(&pd, "/electra/rm", NULL, NULL, (char **)&(const char*[]){ "rm", "-rf", "/Applications/SafeMode.app", NULL }, NULL);
    waitpid(pd, NULL, 0);
    
    unlink("/usr/lib/SBInject.dylib");
    rv = posix_spawn(&pd, "/electra/rm", NULL, NULL, (char **)&(const char*[]){ "rm", "-rf", "/usr/lib/SBInject", NULL }, NULL);
    waitpid(pd, NULL, 0);
    
    unlink("/usr/lib/libsubstitute.0.dylib");
    unlink("/usr/lib/libsubstitute.dylib");
    unlink("/usr/lib/libsubstrate.dylib");
    unlink("/usr/lib/libjailbreak.dylib");
    unlink("/usr/bin/recache");
    unlink("/usr/bin/killall");
    unlink("/usr/share/terminfo");
    unlink("/usr/libexec/sftp-server");
    
    unlink("/usr/lib/SBInject.dylib");
    rv = posix_spawn(&pd, "/electra/rm", NULL, NULL, (char **)&(const char*[]){ "rm", "-rf", "/Library/Frameworks", NULL }, NULL);
    waitpid(pd, NULL, 0);
    
    unlink("/usr/lib/SBInject.dylib");
    rv = posix_spawn(&pd, "/electra/rm", NULL, NULL, (char **)&(const char*[]){ "rm", "-rf", "/System/Library/Themes", NULL }, NULL);
    waitpid(pd, NULL, 0);
    
    rv = posix_spawn(&pd, "/electra/rm", NULL, NULL, (char **)&(const char*[]){ "rm", "-rf", "/bootstrap", NULL }, NULL);
    waitpid(pd, NULL, 0);
    
    unlink("/Library/Themes");
}
