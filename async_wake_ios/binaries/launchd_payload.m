// xcrun -sdk iphoneos clang -dynamiclib -arch arm64 -framework Foundation -o launchd_payload.dylib launchd_payload.m fishhook.c
// jtool --sign --inplace launchd_payload.dylib

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

#define JAILBREAKD_COMMAND_ENTITLE_AND_SIGCONT 2
struct __attribute__((__packed__)) JAILBREAKD_ENTITLE_PID_AND_SIGCONT {
    uint8_t Command;
    int32_t PID;
};

void calljailbreakd(pid_t PID){
#define BUFSIZE 1024
    
    int sockfd, portno, n;
    int serverlen;
    struct sockaddr_in serveraddr;
    struct hostent *server;
    char *hostname;
    char buf[BUFSIZE];
    
    hostname = "127.0.0.1";
    portno = 5;
    
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0)
        printf("ERROR opening socket\n");
    
    /* gethostbyname: get the server's DNS entry */
    server = gethostbyname(hostname);
    if (server == NULL) {
        fprintf(stderr,"ERROR, no such host as %s\n", hostname);
        exit(0);
    }
    
    /* build the server's Internet address */
    bzero((char *) &serveraddr, sizeof(serveraddr));
    serveraddr.sin_family = AF_INET;
    bcopy((char *)server->h_addr,
          (char *)&serveraddr.sin_addr.s_addr, server->h_length);
    serveraddr.sin_port = htons(portno);
    
    /* get a message from the user */
    bzero(buf, BUFSIZE);
    
    struct JAILBREAKD_ENTITLE_PID_AND_SIGCONT entitlePacket;
    entitlePacket.Command = JAILBREAKD_COMMAND_ENTITLE_AND_SIGCONT;
    entitlePacket.PID = PID;
    
    memcpy(buf, &entitlePacket, sizeof(struct JAILBREAKD_ENTITLE_PID_AND_SIGCONT));
    
    serverlen = sizeof(serveraddr);
    n = sendto(sockfd, buf, sizeof(struct JAILBREAKD_ENTITLE_PID_AND_SIGCONT), 0, (const struct sockaddr *)&serveraddr, serverlen);
    if (n < 0)
        printf("Error in sendto\n");
}

int (*old_pspawn)(pid_t * pid, const char* path, const posix_spawn_file_actions_t *file_actions, const posix_spawnattr_t *attrp, char const* argv[], char const* envp[]);
int (*old_pspawnp)(pid_t * pid, const char* file, const posix_spawn_file_actions_t *file_actions, const posix_spawnattr_t *attrp, char const* argv[], char const* envp[]);

int fake_posix_spawn(pid_t * pid, const char* path, const posix_spawn_file_actions_t *file_actions, const posix_spawnattr_t *attrp, char const* argv[], char const* envp[]) {
    return old_pspawn(pid, path, file_actions, attrp, argv, envp);
}

int fake_posix_spawnp(pid_t * pid, const char* file, const posix_spawn_file_actions_t *file_actions, const posix_spawnattr_t *attrp, char const* argv[], char const* envp[]) {
    FILE *f = fopen("/inject_launchd_log.txt", "a");
    fprintf(f, "We got called (fake_posix_spawnp)! %s\n", file);
    
    if (argv != NULL){
        fprintf(f, "Args: \n");
        char** currentarg = argv;
        while (*currentarg != NULL){
            fprintf(f,"\t%s\n", *currentarg);
            currentarg++;
        }
    }
    
    if (strcmp(file, "/usr/libexec/xpcproxy") == 0) {
        if (argv[1] != NULL) {
            if (strstr(argv[1], "com.apple.diagnosticd")
                ||strstr(argv[1], "com.apple.ReportCrash")
                ) {
                fprintf(f, "xpcproxy for diagnosticd or ReportCrash -- no hooking!\n\n");
                fclose(f);
                return old_pspawnp(pid, file, file_actions, attrp, argv, envp);
            }
        }
    }
    
    int envcount = 0;
    
    if (envp != NULL){
        fprintf(f, "Env: \n");
        char** currentenv = envp;
        while (*currentenv != NULL){
            fprintf(f,"\t%s\n", *currentenv);
            if (strstr(*currentenv, "DYLD_INSERT_LIBRARIES") == NULL){
                envcount++;
            }
            currentenv++;
        }
    }
    
    char **newenvp = malloc((envcount+2) * sizeof(char **));
    int j = 0;
    for (int i = 0; i < envcount; i++){
        if (strstr(envp[j], "DYLD_INSERT_LIBRARIES") != NULL){
            continue;
        }
        newenvp[i] = envp[j];
        j++;
    }
    newenvp[j] = "DYLD_INSERT_LIBRARIES=/fun_bins/xpcproxy_payload.dylib";
    newenvp[j+1] = NULL;
    
    fprintf(f, "New Env: \n");
    char **currentenv = newenvp;
    while (*currentenv != NULL){
        fprintf(f,"\t%s\n", *currentenv);
        currentenv++;
    }
    
    posix_spawnattr_t attr;
    posix_spawnattr_t *newattrp = &attr;
    
    if (attrp){
        newattrp = attrp;
        
        short flags;
        posix_spawnattr_getflags(attrp, &flags);
        flags |= POSIX_SPAWN_START_SUSPENDED;
        posix_spawnattr_setflags(attrp, flags);
    } else {
        posix_spawnattr_init(&attr);
        posix_spawnattr_setflags(&attr, POSIX_SPAWN_START_SUSPENDED);
    }
    
    int origret = old_pspawnp(pid, file, file_actions, newattrp, argv, newenvp);
    
    if (pid != NULL){
        fprintf(f, "Got PID: %d\n", *pid);
    
        fprintf(f, "Calling jailbreakd\n");
        calljailbreakd(*pid);
    }
    
    free(newenvp);
    
    fclose(f);
    
    return origret;
}


void* thd_func(void* arg){
    FILE *f = fopen("/inject_launchd_log.txt", "a");
    
    fprintf(f, "In a new thread!\n");
    NSLog(@"In a new thread!");
    
    fclose(f);
    
    rebind_symbols((struct rebinding[2]){
        {"posix_spawn", (void *)fake_posix_spawn, (void **)&old_pspawn},
        {"posix_spawnp", (void *)fake_posix_spawnp, (void **)&old_pspawnp}
    },2);
    return NULL;
}

__attribute__ ((constructor))
static void ctor(void) {
    NSLog(@"Hi there - creating the thread to do our stuff!");
    pthread_t thd;
    pthread_create(&thd, NULL, thd_func, NULL);
}
