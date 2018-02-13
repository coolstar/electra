//
//  unliberios.c
//  electra
//
//  Created by CoolStar on 2/12/18.
//  Copyright © 2018 Electra Team. All rights reserved.
//

#include "unliberios.h"
#include "file_utils.h"
#include <unistd.h>
#include <spawn.h>
#include <sys/wait.h>

bool checkLiberiOS(){
    if (file_exists("/jb"))
        return true;
    if (file_exists("/bin/zsh"))
        return true;
    if (file_exists("/etc/motd"))
        return true;
    return false;
}

void removeLiberiOS(){
//From removeMe.sh
    
    printf("Removing liberiOS...");
    
    int rv;
    pid_t pd;
    
    unlink("/etc/motd");
    unlink("/.cydia_no_stash");
    
    rv = posix_spawn(&pd, "/electra/rm", NULL, NULL, (char **)&(const char*[]){ "rm", "-rf", "/Applications/Cydia.app", NULL }, NULL);
    waitpid(pd, NULL, 0);
    
    rv = posix_spawn(&pd, "/electra/rm", NULL, NULL, (char **)&(const char*[]){ "rm", "-rf", "/usr/share/terminfo", NULL }, NULL);
    waitpid(pd, NULL, 0);
    
    rv = posix_spawn(&pd, "/electra/rm", NULL, NULL, (char **)&(const char*[]){ "rm", "-rf", "/usr/local/bin", NULL }, NULL);
    waitpid(pd, NULL, 0);
    
    rv = posix_spawn(&pd, "/electra/rm", NULL, NULL, (char **)&(const char*[]){ "rm", "-rf", "/usr/local/lib", NULL }, NULL);
    waitpid(pd, NULL, 0);
    
    unlink("/bin/zsh");
    unlink("/etc/profile");
    unlink("/etc/zshrc");
    
    unlink("/usr/bin/scp"); //missing from removeMe.sh oddly
    
    rv = posix_spawn(&pd, "/electra/rm", NULL, NULL, (char **)&(const char*[]){ "rm", "-rf", "/jb", NULL }, NULL);
    waitpid(pd, NULL, 0);
}
