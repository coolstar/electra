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

void cleanup_old() {
    if (file_exists("/bootstrap/")) {
        printf("/bootstrap exists: deleting\n");
        run("rm -rf /bootstrap");
        // whew that felt good
    }
}

void copy_tar() {
    extractTarBinary();
    chmod(tar, 0755);
    inject_trusts(1, (const char **)&(const char*[]){tar});
}

void copy_basebinaries() {
    if (!file_exists("/electra")) {
        mkdir("/electra", 0755);
    }
    
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
    
    posix_spawn(&pd, tar, NULL, NULL, (char **)&(const char*[]){ tar, "-xpzf", progname("basebinaries.tar.gz"), "-C", "/electra", NULL }, NULL);
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
    bool runUICache = true;
    if (file_exists("/Applications/Cydia.app"))
        runUICache = false;
    
    int bootstrapped = open("/.bootstrapped_electra", O_RDONLY);
    if (bootstrapped != -1)
        return post_bootstrap(runUICache);
    
    posix_spawn(&pd, tar, NULL, NULL, (char **)&(const char*[]){ tar, "--preserve-permissions", "--no-overwrite-dir", "-xvzf", progname("bootstrap.tar.gz"), NULL }, NULL);
    waitpid(pd, NULL, 0);
    
    open("/.bootstrapped_electra", O_RDWR|O_CREAT);
    open("/.cydia_no_stash",O_RDWR|O_CREAT);
    
    inject_trusts(1, (const char **)&(const char*[]){"/bin/launchctl"});
    
    symlink("/Library/dpkg/", "/var/lib/dpkg");
    
    printf("[bootstrapper] extracted bootstrap to / \n");
    post_bootstrap(runUICache);
}

void post_bootstrap(const bool runUICache) {
    if (runUICache)
        run("uicache");
    
    unlink(tar);
    
    unlink("/usr/lib/libjailbreak.dylib");
    cp("/usr/lib/libjailbreak.dylib","/electra/libjailbreak.dylib");
    
    inject_trusts(1, (const char **)&(const char*[]){"/bin/launchctl"});
    
    run("launchctl load /Library/LaunchDaemons/dropbear.plist");
    cleanup_old();
    
    printf("[bootstrapper] device has been bootstrapped!\n");
}
