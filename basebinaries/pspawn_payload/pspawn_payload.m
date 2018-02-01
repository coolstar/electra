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
#include <xpc/xpc.h>
#include "libjailbreak_xpc.h"

#ifdef PSPAWN_PAYLOAD_DEBUG
#define LAUNCHD_LOG_PATH "/var/root/pspawn_payload_launchd.log"
// XXX multiple xpcproxies opening same file
// XXX not closing logfile before spawn
#define XPCPROXY_LOG_PATH "/tmp/pspawn_payload_xpcproxy.log"
FILE *log_file;
#define DEBUGLOG(fmt, args...)\
    do {\
        if (log_file == NULL) {\
            log_file = fopen((current_process == PROCESS_LAUNCHD) ? LAUNCHD_LOG_PATH : XPCPROXY_LOG_PATH, "a"); \
            if (log_file == NULL) break; \
        } \
        fprintf(log_file, fmt "\n", ##args); \
        fflush(log_file); \
    } while(0)
#else
#define DEBUGLOG(fmt, args...)
#endif

int file_exist(const char *filename) {
    struct stat buffer;
    int r = stat(filename, &buffer);
    return (r == 0);
}

// LAUNCHD ONLY
jb_connection_t global_jbc = NULL;
// LAUNCHD ONLY

#define PSPAWN_PAYLOAD_DYLIB "/bootstrap/pspawn_payload.dylib"
#define AMFID_PAYLOAD_DYLIB "/bootstrap/amfid_payload.dylib"
#define SBINJECT_PAYLOAD_DYLIB "/usr/lib/SBInject.dylib"

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
    DEBUGLOG("We got called (fake_posix_spawn)! %s", path);

    const char *inject_me = NULL;

    if (current_process == PROCESS_LAUNCHD) {
        if (strcmp(path, "/usr/libexec/xpcproxy") == 0) {
            inject_me = PSPAWN_PAYLOAD_DYLIB;

            const char* startd = argv[1];
            if (startd != NULL) {
                const char **blacklist = xpcproxy_blacklist;

                while (*blacklist) {
                    if (strstr(startd, *blacklist)) {
                        DEBUGLOG("xpcproxy for '%s' which is in blacklist, not injecting", startd);
                        inject_me = NULL;
                        break;
                    }

                    ++blacklist;
                }
            }
        }
    } else if (current_process == PROCESS_XPCPROXY) {
        // XXX inject both SBInject & amfid payload into amfid?
        // note: DYLD_INSERT_LIBRARIES=libfoo1.dylib:libfoo2.dylib
        if (strcmp(path, "/usr/libexec/amfid") == 0) {
            DEBUGLOG("Starting amfid -- special handling");
            inject_me = AMFID_PAYLOAD_DYLIB;
        } else {
            inject_me = SBINJECT_PAYLOAD_DYLIB;
        }
    }

    // XXX log different err on inject_me == NULL and nonexistent inject_me
    if (inject_me == NULL || !file_exist(inject_me)) {
        DEBUGLOG("Nothing to inject");
        return old(pid, path, file_actions, attrp, argv, envp);
    }

    DEBUGLOG("Injecting %s into %s", inject_me, path);

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

    char *envp_inject = malloc(strlen("DYLD_INSERT_LIBRARIES=") + strlen(inject_me) + 1);

    envp_inject[0] = '\0';
    strcat(envp_inject, "DYLD_INSERT_LIBRARIES=");
    strcat(envp_inject, inject_me);

    newenvp[j] = envp_inject;
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

// for logging purposes only
#define FLAG_ATTRIBUTE_XPCPROXY (1 << 17)
#define FLAG_ATTRIBUTE_LAUNCHD  (1 << 16)

    if (current_process == PROCESS_XPCPROXY) {
        // dont leak logging fd into execd process
#ifdef PSPAWN_PAYLOAD_DEBUG
        if (log_file != NULL) {
            fclose(log_file);
            log_file = NULL;
        }
#endif
        jb_oneshot_entitle_now(getpid(), FLAG_ENTITLE | FLAG_PLATFORMIZE | FLAG_SANDBOX | FLAG_SIGCONT | FLAG_WAIT_EXEC | FLAG_ATTRIBUTE_XPCPROXY);
        origret = old(pid, path, file_actions, newattrp, argv, newenvp);
    } else {
        int gotpid;
        origret = old(&gotpid, path, file_actions, newattrp, argv, newenvp);

        if (origret == 0) {
            if (pid != NULL) *pid = gotpid;
            jb_entitle_now(global_jbc, gotpid, FLAG_ENTITLE | FLAG_PLATFORMIZE | FLAG_SANDBOX | FLAG_SIGCONT | FLAG_ATTRIBUTE_LAUNCHD);
        }
    }

#undef FLAG_ATTRIBUTE_XPCPROXY
#undef FLAG_ATTRIBUTE_LAUNCHD

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

xpc_object_t xpc_pipe_create_from_port(mach_port_t, int);
void stek(pid_t bootstrap_donor_pid) {
    /* see: https://codeshare.frida.re/@stek29/launchd-xpc-hack/ */

    void **once_table = dlsym(RTLD_DEFAULT, "_os_alloc_once_table") + 0x18;
    void *xpg_gd__a = *(once_table);
    void *xpg_gd__xpc_flags = *(once_table) + 0x8;
    void *xpg_gd__task_bootstrap_port = *(once_table) + 0x10;
    void *xpg_gd__xpc_bootstrap_pipe = *(once_table) + 0x18;

    DEBUGLOG("stek:: %p %p %p %p", xpg_gd__a, xpg_gd__xpc_flags, xpg_gd__task_bootstrap_port, xpg_gd__xpc_bootstrap_pipe);

    mach_port_t tfpwho = MACH_PORT_NULL;
    task_for_pid(mach_task_self(), bootstrap_donor_pid, &tfpwho);

    mach_port_t bp = MACH_PORT_NULL;
    task_get_special_port(tfpwho, 4, &bp);

    DEBUGLOG("stek:: tfp20 %x bp %x", tfpwho, bp);

    memcpy(xpg_gd__task_bootstrap_port, &bp, 4);

    // sync everywhere
    task_set_special_port(mach_task_self(), 4, bp);
    memcpy(dlsym(RTLD_DEFAULT, "bootstrap_port"), &bp, 4);

    xpc_object_t bpipe = xpc_pipe_create_from_port(bp, 0);
    memcpy(xpg_gd__xpc_bootstrap_pipe, &bpipe, 8);

    uint64_t w = 0x1000000;
    memcpy(xpg_gd__a, &w, 8); // likely initialization state
}

void* thd_func(void* arg){
    DEBUGLOG("In a new thread!");

    int fd = open("/tmp/jailbreakd.pid", O_RDONLY, 0600);
    if (fd < 0) {
        DEBUGLOG("panic! jailbreakd's pidfile doesn't exist!!");
    }
    char pid[8] = {0};
    read(fd, pid, 8);
    pid_t donor = atoi(pid);
    close(fd);

    DEBUGLOG("who's that pokemon: %d", donor);

    stek(donor);
    global_jbc = jb_connect();
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
