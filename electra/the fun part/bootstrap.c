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
    unlink("/bin/launchctl");
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
    
    unlink("/usr/libexec/cydia/move.sh");
    
    FILE *file = fopen("/etc/hosts","w"); /* write file (create a file if it does not exist and if it does treat as empty.*/
    fprintf(file,"%s","##\n"); //writes
    fprintf(file,"%s","# Host Database\n"); //writes
    fprintf(file,"%s","# localhost is used to configure the loopback interface\n"); //writes
    fprintf(file,"%s","# when the system is booting.  Do not change this entry.\n"); //writes
    fprintf(file,"%s","##\n"); //writes
    fprintf(file,"%s","127.0.0.1    localhost\n"); //writes
    fprintf(file,"%s","255.255.255.255 broadcasthost\n"); //writes
    fprintf(file,"%s","::1      localhost\n"); //writes
    fclose(file); /*done!*/
    
    file = fopen("/etc/apt/sources.list.d/electra-shim.list","w"); /* write file (create a file if it does not exist and if it does treat as empty.*/
    fprintf(file,"%s","deb https://electrarepo64.coolstar.org/substrate-shim/ ./\n"); //writes
    fprintf(file,"%s","\n"); //writes
    fclose(file);
    
    cp("/usr/libexec/cydia/move.sh", progname("move.sh"));
    
    int rv = open("/.bootstrapped_electra", O_RDWR|O_CREAT);
    close(rv);
    rv = open("/.cydia_no_stash",O_RDWR|O_CREAT);
    close(rv);
    
    printf("[bootstrapper] extracted bootstrap to / \n");
    post_bootstrap(true);
}

void post_bootstrap(const bool runUICache) {
    pid_t pd;
    if (runUICache){
        posix_spawn(&pd, "/usr/bin/uicache", NULL, NULL, (char **)&(const char*[]){ "uicache", NULL }, NULL);
        waitpid(pd, NULL, 0);
    }
    
    unlink(tar);
    
    FILE *file;
    file = fopen("/etc/apt/sources.list.d/electra.list","w"); /* write file (create a file if it does not exist and if it does treat as empty.*/
    fprintf(file,"%s","deb https://electrarepo64.coolstar.org/ ./\n"); //writes
    fprintf(file,"%s","\n"); //writes
    fclose(file);
    
    unlink("/usr/lib/libjailbreak.dylib");
    cp("/usr/lib/libjailbreak.dylib","/electra/libjailbreak.dylib");
    
    inject_trusts(1, (const char **)&(const char*[]){"/bin/launchctl"});
    
    int rv = open("/var/lib/dpkg/available", O_RDWR|O_CREAT);
    close(rv);
    
    posix_spawn(&pd, "/bin/bash", NULL, NULL, (char **)&(const char*[]){ "bash", "/usr/libexec/cydia/firmware.sh", NULL }, NULL);
    waitpid(pd, NULL, 0);
    
    posix_spawn(&pd, "/bin/bash", NULL, NULL, (char **)&(const char*[]){ "bash", "/Library/dpkg/info/openssh.postinst", NULL }, NULL);
    waitpid(pd, NULL, 0);
    
    posix_spawn(&pd, "/bin/launchctl", NULL, NULL, (char **)&(const char*[]){ "launchctl", "load", "/Library/LaunchDaemons/com.openssh.sshd.plist", NULL }, NULL);
    waitpid(pd, NULL, 0);
    
    run("rm /var/lib/apt/lists/apt.saurik.com*");
    blockSaurikRepo();
    
    char *myenviron[] = {
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/bin/X11:/usr/games",
        "PS1=\\h:\\w \\u\\$ ",
        NULL
    };
    posix_spawn(&pd, "/usr/bin/dpkg", NULL, NULL, (char **)&(const char*[]){ "dpkg", "-i", "--refuse-downgrade", progname("apt7-lib_0.7.25.3-16-coolstar_iphoneos-arm.deb"), NULL }, (char **)&myenviron);
    waitpid(pd, NULL, 0);
    
    printf("[bootstrapper] device has been bootstrapped!\n");
    
    if (runUICache){
        cydiaDone();
    }
}
