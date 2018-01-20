#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <spawn.h>
#include <sys/types.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/sysctl.h>
#include <dlfcn.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <pthread.h>
#include <Foundation/Foundation.h>
#include "fishhook.h"
#include "common.h"

#define LAUNCHD_DYLIB "/bootstrap/pspawn_payload.dylib"
#define XPCPROXY_DYLIB "/usr/lib/SBInject.dylib"

// since this dylib should only be loaded into launchd and xpcproxy
// it's safe to assume that we're in xpcproxy if getpid() != 1
enum currentprocess {
    PROCESS_LAUNCHD,
    PROCESS_XPCPROXY,
};

int current_process = PROCESS_XPCPROXY;

const char* xpcproxy_blacklist[] = {
    "com.apple.diagnosticd",  // syslog
    "com.apple.ReportCrash",  // crash reporting
    "MTLCompilerService",     // ?_?
    "OTAPKIAssetTool",        // h_h
    "cfprefsd",               // o_o
    "jailbreakd",             // don't inject into jbd since we'd have to call to it
    NULL
};

typedef int (*pspawn_t)(pid_t * pid, const char* path, const posix_spawn_file_actions_t *file_actions, posix_spawnattr_t *attrp, char const* argv[], char* envp[]);

pspawn_t old_pspawn, old_pspawnp;

int fake_posix_spawn_common(pid_t * pid, const char* path, const posix_spawn_file_actions_t *file_actions, posix_spawnattr_t *attrp, char const* argv[], char* envp[], pspawn_t old) {
    if (current_process == PROCESS_XPCPROXY && !file_exist(XPCPROXY_DYLIB)) {
        return old(pid, path, file_actions, attrp, argv, envp);
    } else if (current_process == PROCESS_LAUNCHD && !file_exist(LAUNCHD_DYLIB)) {
        if ((strcmp(path, "/usr/libexec/xpcproxy") == 0) && argv[1] != NULL) {
            const char **blacklist = xpcproxy_blacklist;

            while (blacklist) {
                if (strstr(argv[1], *blacklist)) {
                    NSLog(@"xpcproxy for %s which is in blacklist, not injecting\n", argv[1]);
                    return old(pid, path, file_actions, attrp, argv, envp);
                }

                ++blacklist;
            }
        }
    }
    
#if PSPAWN_PAYLOAD_DEBUG
    FILE *f = fopen("/var/mobile/inject_xpcproxyd_log.txt", "a");
    fprintf(f, "We got called (fake_posix_spawn)! %s\n", path);
    
    if (argv != NULL){
        fprintf(f, "Args: \n");
        char** currentarg = argv;
        while (*currentarg != NULL){
            fprintf(f,"\t%s\n", *currentarg);
            currentarg++;
        }
    }
    
    fclose(f);
    f = fopen("/var/mobile/inject_xpcproxyd_log.txt", "a");
#endif
    
    int envcount = 0;
    
    if (envp != NULL){
#if PSPAWN_PAYLOAD_DEBUG
        fprintf(f, "Env: \n");
#endif
        char** currentenv = envp;
        while (*currentenv != NULL){
#if PSPAWN_PAYLOAD_DEBUG
            fprintf(f,"\t%s\n", *currentenv);
#endif
            if (strstr(*currentenv, "DYLD_INSERT_LIBRARIES") == NULL){
                envcount++;
            }
            currentenv++;
        }
    }
    
#if PSPAWN_PAYLOAD_DEBUG
    fclose(f);
    f = fopen("/var/mobile/inject_xpcproxyd_log.txt", "a");
#endif
    
    char **newenvp = malloc((envcount+2) * sizeof(char **));
    int j = 0;
    for (int i = 0; i < envcount; i++){
        if (strstr(envp[j], "DYLD_INSERT_LIBRARIES") != NULL){
            continue;
        }
        newenvp[i] = envp[j];
        j++;
    }
    if (current_process == PROCESS_LAUNCHD) {
        newenvp[j] =  "DYLD_INSERT_LIBRARIES=" LAUNCHD_DYLIB;
    } else if (current_process == PROCESS_XPCPROXY) {
        newenvp[j] = "DYLD_INSERT_LIBRARIES=" XPCPROXY_DYLIB;
    }
    newenvp[j+1] = NULL;
    
#if PSPAWN_PAYLOAD_DEBUG
    fprintf(f, "New Env: \n");
    char** currentenv = newenvp;
    while (*currentenv != NULL){
        fprintf(f,"\t%s\n", *currentenv);
        currentenv++;
    }
    
    fclose(f);
    f = fopen("/var/mobile/inject_xpcproxyd_log.txt", "a");
#endif
    
    posix_spawnattr_t attr;
    
    posix_spawnattr_t *newattrp = &attr;
    
    if (attrp) {
        newattrp = attrp;
        
#if PSPAWN_PAYLOAD_DEBUG
        fprintf(f, "got attrp\n");
        fclose(f);
        f = fopen("/var/mobile/inject_xpcproxyd_log.txt", "a");
#endif
        
        short flags;
        posix_spawnattr_getflags(attrp, &flags);
        flags |= POSIX_SPAWN_START_SUSPENDED;
        posix_spawnattr_setflags(attrp, flags);
    } else {
        posix_spawnattr_init(&attr);
        posix_spawnattr_setflags(&attr, POSIX_SPAWN_START_SUSPENDED);
    }
    
#if PSPAWN_PAYLOAD_DEBUG
    fprintf(f, "Calling jailbreakd\n");
    fclose(f);
#endif

    int origret;

    if (current_process == PROCESS_XPCPROXY) {
        calljailbreakd(getpid(), JAILBREAKD_COMMAND_ENTITLE_AND_SIGCONT_AFTER_DELAY);
        origret = old_pspawn(pid, path, file_actions, newattrp, argv, newenvp);
    } else {
        int gotpid;
        origret = old_pspawn(&gotpid, path, file_actions, newattrp, argv, newenvp);

        if (origret == 0) {
            if (pid != NULL) *pid = gotpid;
            calljailbreakd(gotpid, JAILBREAKD_COMMAND_ENTITLE_AND_SIGCONT);
        }
    }
    
    return origret;
}


int fake_posix_spawn(pid_t * pid, const char* file, const posix_spawn_file_actions_t *file_actions, posix_spawnattr_t *attrp, const char* argv[], char* envp[]) {
    return fake_posix_spawn_common(pid, file, file_actions, attrp, argv, envp, old_pspawn);
}

int fake_posix_spawnp(pid_t * pid, const char* file, const posix_spawn_file_actions_t *file_actions, posix_spawnattr_t *attrp, const char* argv[], char* envp[]) {
    return fake_posix_spawn_common(pid, file, file_actions, attrp, argv, envp, old_pspawnp);
}


void rebind_pspawns(void) {
    struct rebinding rebindings[] = {
        {"posix_spawn", (void *)fake_posix_spawn, (void **)&old_pspawn},
        {"posix_spawnp", (void *)fake_posix_spawnp, (void **)&old_pspawnp},
    };

    rebind_symbols(rebindings, 2);
}

void* thd_func(void* arg){
    NSLog(@"In a new thread!");
    rebind_pspawns();
    return NULL;
}

__attribute__ ((constructor))
static void ctor(void) {
    if (getpid() == 1) {
        current_process = PROCESS_LAUNCHD;
        pthread_t thd;
        pthread_create(&thd, NULL, thd_func, NULL);
    } else {
       current_process = PROCESS_XPCPROXY;
       rebind_pspawns();
    }
}
