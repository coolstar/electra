//
//  bootstrap.c
//  electra
//
//  Created by Jamie Bishop on 11/02/2018.
//  Copyright © 2018 Electra Team. All rights reserved.
//

#include "bootstrap.h"
#include "file_utils.h"
#include "fun_objc.h"
#include "amfi_utils.h"
#include "utils.h"
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/fcntl.h>
#include <unistd.h>
#include <spawn.h>

#define tar "/electra/tar"

pid_t pd;

void copy_tar() {
    extractGz("tar", "/electra/tar");
    chmod(tar, 0755);
    inject_trusts(1, (const char **)&(const char*[]){tar});
}

void copy_basebinaries() {
    mkdir("/electra", 0755);
    
    copy_tar();
    
    // Remove old base binaries
    unlink("/electra/inject_amfid");
    unlink("/electra/inject_launchd");
    unlink("/electra/launchd_payload.dylib");
    unlink("/electra/xpcproxy_payload.dylib");
    
    unlink("/electra/inject_ctriticald");
    unlink("/electra/pspawn_payload.dylib");
    
    unlink("/electra/amfid_payload.dylib");
    unlink("/electra/launchjailbreak");
    unlink("/electra/jailbreakd");
    
    extractGz("rm","/electra/rm");
    chmod("/electra/rm", 0755);
    
    posix_spawn(&pd, tar, NULL, NULL, (char **)&(const char*[]){ tar, "-xpf", progname("basebinaries.tar"), "-C", "/electra", NULL }, NULL);
    waitpid(pd, NULL, 0);
    
    printf("[bootstrapper] copied the required binaries into the right places\n");
    
    inject_trusts(4, (const char **)&(const char*[]){
        "/electra/inject_criticald",
        "/electra/amfid_payload.dylib",
        "/electra/pspawn_payload.dylib",
        "/electra/libjailbreak.dylib"
    });
}

void extract_bootstrap() {
    extractGz("launchctl", "/electra/launchctl");
    cp("/bin/launchctl", "/electra/launchctl");
    chmod("/bin/launchctl", 0755);
    unlink("/electra/launchctl");
    
    int bootstrapped = open("/.bootstrapped_electra", O_RDONLY);
    if (bootstrapped != -1) {
        close(bootstrapped);
        return post_bootstrap(false);
    }
    close(bootstrapped);
    
    installingCydia();
    
    extractGz("bootstrap.tar", "/electra/bootstrap.tar");
    
    posix_spawn(&pd, tar, NULL, NULL, (char **)&(const char*[]){ tar, "--preserve-permissions", "-xvkf", "/electra/bootstrap.tar", "-C", "/", NULL }, NULL);
    waitpid(pd, NULL, 0);
    
    unlink("/electra/bootstrap.tar");
    
    int rv = open("/.bootstrapped_electra", O_RDWR|O_CREAT);
    close(rv);
    rv = open("/.cydia_no_stash",O_RDWR|O_CREAT);
    close(rv);
    
    printf("[bootstrapper] extracted bootstrap to / \n");
    post_bootstrap(true);
}

void post_bootstrap(const bool runUICache) {
    if (runUICache)
        run("uicache");
    
    unlink(tar);
    
    unlink("/usr/lib/libjailbreak.dylib");
    cp("/usr/lib/libjailbreak.dylib","/electra/libjailbreak.dylib");
    
    inject_trusts(1, (const char **)&(const char*[]){"/bin/launchctl"});
    
    run("/Library/dpkg/info/openssh.postinst");
    
    run("/bin/launchctl load /Library/LaunchDaemons/com.openssh.sshd.plist");
    
    printf("[bootstrapper] device has been bootstrapped!\n");
}
