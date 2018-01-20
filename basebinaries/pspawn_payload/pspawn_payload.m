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

#ifdef PSPAWN_PAYLOAD_DEBUG
#define LAUNCHD_LOG_PATH "/tmp/pspawn_payload_launchd.log"
FILE *launchd_log_file;
#define DEBUGLOG(fmt, args...)\
    do {\
        if (current_process == PROCESS_LAUNCHD) {\
            if (launchd_log_file == NULL) launchd_log_file = fopen(LAUNCHD_LOG_PATH, "a"); \
            if (launchd_log_file == NULL) break; \
            fprintf(launchd_log_file, fmt "\n", ##args); \
            fflush(launchd_log_file); \
        } else { \
            NSLog(@"" fmt, ##args);\
        }\
    } while(0)
#else
#define DEBUGLOG(fmt, args...)
#endif

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

typedef int (*pspawn_t)(pid_t * pid, const char* path, const posix_spawn_file_actions_t *file_actions, posix_spawnattr_t *attrp, char const* argv[], const char* envp[]);

pspawn_t old_pspawn, old_pspawnp;

int fake_posix_spawn_common(pid_t * pid, const char* path, const posix_spawn_file_actions_t *file_actions, posix_spawnattr_t *attrp, char const* argv[], const char* envp[], pspawn_t old) {
    if (current_process == PROCESS_XPCPROXY && !file_exist(XPCPROXY_DYLIB)) {
        return old(pid, path, file_actions, attrp, argv, envp);
    } else if (current_process == PROCESS_LAUNCHD && !file_exist(LAUNCHD_DYLIB)) {
        return old(pid, path, file_actions, attrp, argv, envp);
    } else if (current_process == PROCESS_LAUNCHD && file_exist(LAUNCHD_DYLIB)){
        if ((strcmp(path, "/usr/libexec/xpcproxy") == 0) && argv[1] != NULL) {
            const char **blacklist = xpcproxy_blacklist;

            while (*blacklist) {
                if (strstr(argv[1], *blacklist)) {
                    DEBUGLOG("xpcproxy for %s which is in blacklist, not injecting", argv[1]);
                    return old(pid, path, file_actions, attrp, argv, envp);
                }

                ++blacklist;
            }
        }
    }

    DEBUGLOG("We got called (fake_posix_spawn)! %s", path);

#ifdef PSPAWN_PAYLOAD_DEBUG
    if (argv != NULL){
        DEBUGLOG("Args: ");
        const char** currentarg = argv;
        while (*currentarg != NULL){
            DEBUGLOG("\t%s", *currentarg);
            currentarg++;
        }
    }
#endif

    int envcount = 0;

    if (envp != NULL){
        DEBUGLOG("Env: ");
        const char** currentenv = envp;
        while (*currentenv != NULL){
            DEBUGLOG("\t%s", *currentenv);
            if (strstr(*currentenv, "DYLD_INSERT_LIBRARIES") == NULL) {
                envcount++;
            }
            currentenv++;
        }
    }

    char const** newenvp = malloc((envcount+2) * sizeof(char **));
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
    DEBUGLOG("New Env:");
    const char** currentenv = newenvp;
    while (*currentenv != NULL){
        DEBUGLOG("\t%s", *currentenv);
        currentenv++;
    }
#endif

    posix_spawnattr_t attr;

    posix_spawnattr_t *newattrp = &attr;

    if (attrp) {
        newattrp = attrp;
        short flags;
        posix_spawnattr_getflags(attrp, &flags);
        flags |= POSIX_SPAWN_START_SUSPENDED;
        posix_spawnattr_setflags(attrp, flags);
    } else {
        posix_spawnattr_init(&attr);
        posix_spawnattr_setflags(&attr, POSIX_SPAWN_START_SUSPENDED);
    }

    int origret;

    if (current_process == PROCESS_XPCPROXY) {
        calljailbreakd(getpid(), JAILBREAKD_COMMAND_ENTITLE_AND_SIGCONT_AFTER_DELAY);
        origret = old(pid, path, file_actions, newattrp, argv, newenvp);
    } else {
        int gotpid;
        origret = old(&gotpid, path, file_actions, newattrp, argv, newenvp);

        if (origret == 0) {
            if (pid != NULL) *pid = gotpid;
            calljailbreakd(gotpid, JAILBREAKD_COMMAND_ENTITLE_AND_SIGCONT);
        }
    }

    return origret;
}


int fake_posix_spawn(pid_t * pid, const char* file, const posix_spawn_file_actions_t *file_actions, posix_spawnattr_t *attrp, const char* argv[], const char* envp[]) {
    return fake_posix_spawn_common(pid, file, file_actions, attrp, argv, envp, old_pspawn);
}

int fake_posix_spawnp(pid_t * pid, const char* file, const posix_spawn_file_actions_t *file_actions, posix_spawnattr_t *attrp, const char* argv[], const char* envp[]) {
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
