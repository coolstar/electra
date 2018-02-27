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

void cleanupPotentialManualFiles(){
    int rv;
    pid_t pd;
    
    unlink("/bin/bash");
    unlink("/authorize.sh");
    
    rv = posix_spawn(&pd, "/electra/rm", NULL, NULL, (char **)&(const char*[]){ "rm", "-rf", "/Applications/jjjj.app", NULL }, NULL);
    waitpid(pd, NULL, 0);
    
    rv = posix_spawn(&pd, "/electra/rm", NULL, NULL, (char **)&(const char*[]){ "rm", "-rf", "/Applications/Extender.app", NULL }, NULL);
    waitpid(pd, NULL, 0);
    
    rv = posix_spawn(&pd, "/electra/rm", NULL, NULL, (char **)&(const char*[]){ "rm", "-rf", "/Applications/GBA4iOS.app", NULL }, NULL);
    waitpid(pd, NULL, 0);
    
    rv = posix_spawn(&pd, "/electra/rm", NULL, NULL, (char **)&(const char*[]){ "rm", "-rf", "/Applications/Filza.app", NULL }, NULL);
    waitpid(pd, NULL, 0);
    
    posix_spawn(&pd, "/electra/rm", NULL, NULL, (char **)&(const char*[]){ "rm", "-rf", "/Library/dpkg", NULL }, NULL);
    waitpid(pd, NULL, 0);
    
    rv = posix_spawn(&pd, "/electra/rm", NULL, NULL, (char **)&(const char*[]){ "rm", "-rf", "/Library/Cylinder", NULL }, NULL);
    waitpid(pd, NULL, 0);
    
    rv = posix_spawn(&pd, "/electra/rm", NULL, NULL, (char **)&(const char*[]){ "rm", "-rf", "/Library/LaunchDaemons", NULL }, NULL);
    waitpid(pd, NULL, 0);
    
    rv = posix_spawn(&pd, "/electra/rm", NULL, NULL, (char **)&(const char*[]){ "rm", "-rf", "/Library/Zeppelin", NULL }, NULL);
    waitpid(pd, NULL, 0);
    
    posix_spawn(&pd, "/electra/rm", NULL, NULL, (char **)&(const char*[]){ "rm", "-rf", "/etc/alternatives", NULL }, NULL);
    waitpid(pd, NULL, 0);
    
    posix_spawn(&pd, "/electra/rm", NULL, NULL, (char **)&(const char*[]){ "rm", "-rf", "/etc/apt", NULL }, NULL);
    waitpid(pd, NULL, 0);
    
    posix_spawn(&pd, "/electra/rm", NULL, NULL, (char **)&(const char*[]){ "rm", "-rf", "/etc/dpkg", NULL }, NULL);
    waitpid(pd, NULL, 0);
    
    posix_spawn(&pd, "/electra/rm", NULL, NULL, (char **)&(const char*[]){ "rm", "-rf", "/etc/dropbear", NULL }, NULL);
    waitpid(pd, NULL, 0);
    
    posix_spawn(&pd, "/electra/rm", NULL, NULL, (char **)&(const char*[]){ "rm", "-rf", "/etc/pam.d", NULL }, NULL);
    waitpid(pd, NULL, 0);
    
    posix_spawn(&pd, "/electra/rm", NULL, NULL, (char **)&(const char*[]){ "rm", "-rf", "/etc/profile.d", NULL }, NULL);
    waitpid(pd, NULL, 0);
    
    posix_spawn(&pd, "/electra/rm", NULL, NULL, (char **)&(const char*[]){ "rm", "-rf", "/etc/ssh", NULL }, NULL);
    waitpid(pd, NULL, 0);
    
    posix_spawn(&pd, "/electra/rm", NULL, NULL, (char **)&(const char*[]){ "rm", "-rf", "/usr/include", NULL }, NULL);
    waitpid(pd, NULL, 0);
    
    posix_spawn(&pd, "/electra/rm", NULL, NULL, (char **)&(const char*[]){ "rm", "-rf", "/usr/lib/apt", NULL }, NULL);
    waitpid(pd, NULL, 0);
    
    posix_spawn(&pd, "/electra/rm", NULL, NULL, (char **)&(const char*[]){ "rm", "-rf", "/usr/lib/dpkg", NULL }, NULL);
    waitpid(pd, NULL, 0);
    
    posix_spawn(&pd, "/electra/rm", NULL, NULL, (char **)&(const char*[]){ "rm", "-rf", "/usr/lib/pam", NULL }, NULL);
    waitpid(pd, NULL, 0);
    
    posix_spawn(&pd, "/electra/rm", NULL, NULL, (char **)&(const char*[]){ "rm", "-rf", "/usr/lib/pkgconfig", NULL }, NULL);
    waitpid(pd, NULL, 0);
    
    posix_spawn(&pd, "/electra/rm", NULL, NULL, (char **)&(const char*[]){ "rm", "-rf", "/usr/lib/cycript0.9", NULL }, NULL);
    waitpid(pd, NULL, 0);
    
    posix_spawn(&pd, "/electra/rm", NULL, NULL, (char **)&(const char*[]){ "rm", "-rf", "/usr/libexec/cydia", NULL }, NULL);
    waitpid(pd, NULL, 0);
    
    posix_spawn(&pd, "/electra/rm", NULL, NULL, (char **)&(const char*[]){ "rm", "-rf", "/usr/libexec/gnupg", NULL }, NULL);
    waitpid(pd, NULL, 0);
    
    posix_spawn(&pd, "/electra/rm", NULL, NULL, (char **)&(const char*[]){ "rm", "-rf", "/usr/share/bigboss", NULL }, NULL);
    waitpid(pd, NULL, 0);
    
    posix_spawn(&pd, "/electra/rm", NULL, NULL, (char **)&(const char*[]){ "rm", "-rf", "/usr/share/dpkg", NULL }, NULL);
    waitpid(pd, NULL, 0);
    
    posix_spawn(&pd, "/electra/rm", NULL, NULL, (char **)&(const char*[]){ "rm", "-rf", "/usr/share/gnupg", NULL }, NULL);
    waitpid(pd, NULL, 0);
    
    posix_spawn(&pd, "/electra/rm", NULL, NULL, (char **)&(const char*[]){ "rm", "-rf", "/usr/share/tabset", NULL }, NULL);
    waitpid(pd, NULL, 0);
    
    posix_spawn(&pd, "/electra/rm", NULL, NULL, (char **)&(const char*[]){ "rm", "-rf", "/var/cache/apt", NULL }, NULL);
    waitpid(pd, NULL, 0);
    
    posix_spawn(&pd, "/electra/rm", NULL, NULL, (char **)&(const char*[]){ "rm", "-rf", "/var/db/stash", NULL }, NULL);
    waitpid(pd, NULL, 0);
    
    posix_spawn(&pd, "/electra/rm", NULL, NULL, (char **)&(const char*[]){ "rm", "-rf", "/var/lib/apt", NULL }, NULL);
    waitpid(pd, NULL, 0);
    
    posix_spawn(&pd, "/electra/rm", NULL, NULL, (char **)&(const char*[]){ "rm", "-rf", "/var/lib/dpkg", NULL }, NULL);
    waitpid(pd, NULL, 0);
    
    posix_spawn(&pd, "/electra/rm", NULL, NULL, (char **)&(const char*[]){ "rm", "-rf", "/var/stash", NULL }, NULL);
    waitpid(pd, NULL, 0);
    
    posix_spawn(&pd, "/electra/rm", NULL, NULL, (char **)&(const char*[]){ "rm", "-rf", "/var/tweak", NULL }, NULL);
    waitpid(pd, NULL, 0);
}

void removeElectraBeta(void){
    cleanupPotentialManualFiles();
    
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
    
    rv = posix_spawn(&pd, "/electra/rm", NULL, NULL, (char **)&(const char*[]){ "rm", "-rf", "/System/Library/Themes", NULL }, NULL);
    waitpid(pd, NULL, 0);
    
    rv = posix_spawn(&pd, "/electra/rm", NULL, NULL, (char **)&(const char*[]){ "rm", "-rf", "/bootstrap", NULL }, NULL);
    waitpid(pd, NULL, 0);
    
    rv = posix_spawn(&pd, "/electra/rm", NULL, NULL, (char **)&(const char*[]){ "rm", "-rf", "/Library/Themes", NULL }, NULL);
    waitpid(pd, NULL, 0);
    
    unlink("/usr/lib/SBInject.dylib");
    
    rv = posix_spawn(&pd, "/electra/rm", NULL, NULL, (char **)&(const char*[]){ "rm", "-rf", "/Library/MobileSubstrate", NULL }, NULL);
    waitpid(pd, NULL, 0);
}
