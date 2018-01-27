#import <Foundation/Foundation.h>
#include <stdio.h>
#include <mach/mach.h>
#include <mach/error.h>
#include <mach/message.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "patchfinder64.h"
#include "kern_utils.h"
#include "kmem.h"
#include "kexecute.h"

#define PROC_PIDPATHINFO_MAXSIZE  (4*MAXPATHLEN)
int proc_pidpath(pid_t pid, void *buffer, uint32_t buffersize);

#define JAILBREAKD_COMMAND_ENTITLE 1
#define JAILBREAKD_COMMAND_ENTITLE_AND_SIGCONT 2
#define JAILBREAKD_COMMAND_ENTITLE_PLATFORMIZE 3
#define JAILBREAKD_COMMAND_ENTITLE_AND_SIGCONT_AFTER_DELAY 4
#define JAILBREAKD_COMMAND_ENTITLE_AND_SIGCONT_FROM_XPCPROXY 5
#define JAILBREAKD_COMMAND_DUMP_CRED 7
#define JAILBREAKD_COMMAND_EXIT 13

struct __attribute__((__packed__)) JAILBREAKD_PACKET {
    uint8_t Command;
};

struct __attribute__((__packed__)) JAILBREAKD_ENTITLE_PID {
    uint8_t Command;
    int32_t Pid;
};

struct __attribute__((__packed__)) JAILBREAKD_ENTITLE_PID_AND_SIGCONT {
    uint8_t Command;
    int32_t Pid;
};

struct __attribute__((__packed__)) JAILBREAKD_ENTITLE_PLATFORMIZE_PID {
    uint8_t Command;
    int32_t EntitlePID;
    int32_t PlatformizePID;
};

struct __attribute__((__packed__)) JAILBREAKD_DUMP_CRED {
    uint8_t Command;
    int32_t Pid;
};

mach_port_t tfpzero;
uint64_t kernel_base;
uint64_t kernel_slide;

#define MEMORYSTATUS_CMD_SET_JETSAM_TASK_LIMIT 6
int memorystatus_control(uint32_t command, int32_t pid, uint32_t flags, void *buffer, size_t buffersize);

int remove_memory_limit(void) {
    // daemons run under launchd have a very stingy memory limit by default, we need
    // quite a bit more for patchfinder so disable it here
    // (note that we need the com.apple.private.memorystatus entitlement to do so)
    pid_t my_pid = getpid();
    return memorystatus_control(MEMORYSTATUS_CMD_SET_JETSAM_TASK_LIMIT, my_pid, 0, NULL, 0);
}

extern unsigned offsetof_ip_kobject;

int runserver(){
    NSLog(@"[jailbreakd] Process Start!");
    remove_memory_limit();

    kern_return_t err = host_get_special_port(mach_host_self(), HOST_LOCAL_NODE, 4, &tfpzero);
    if (err != KERN_SUCCESS) {
        NSLog(@"host_get_special_port 4: %s", mach_error_string(err));
        return 5;
    }

    init_kernel(kernel_base, NULL);
    // Get the slide
    kernel_slide = kernel_base - 0xFFFFFFF007004000;
    NSLog(@"[jailbreakd] slide: 0x%016llx", kernel_slide);

    init_kexecute();

    struct sockaddr_in serveraddr; /* server's addr */
    struct sockaddr_in clientaddr; /* client addr */

    NSLog(@"[jailbreakd] Running server...");
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0)
        NSLog(@"[jailbreakd] Error opening socket");
    int optval = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (const void *)&optval, sizeof(int));

    struct hostent *server;
    char *hostname = "127.0.0.1";
    /* gethostbyname: get the server's DNS entry */
    server = gethostbyname(hostname);
    if (server == NULL) {
        NSLog(@"[jailbreakd] ERROR, no such host as %s", hostname);
        exit(0);
    }

    bzero((char *) &serveraddr, sizeof(serveraddr));
    serveraddr.sin_family = AF_INET;
    //serveraddr.sin_addr.s_addr = htonl(INADDR_ANY);
    bcopy((char *)server->h_addr,
          (char *)&serveraddr.sin_addr.s_addr, server->h_length);
    serveraddr.sin_port = htons((unsigned short)5);

    if (bind(sockfd, (struct sockaddr *)&serveraddr, sizeof(serveraddr)) < 0){
        NSLog(@"[jailbreakd] Error binding...");
        term_kernel();
        term_kexecute();
        exit(-1);
    }
    NSLog(@"[jailbreakd] Server running!");
    
    unlink("/var/tmp/jailbreakd.pid");
    
    FILE *f = fopen("/var/tmp/jailbreakd.pid", "w");
    fprintf(f, "%d\n", getpid());
    fclose(f);

    char buf[1024];

    socklen_t clientlen = sizeof(clientaddr);
    while (1){
        bzero(buf, 1024);
        int size = recvfrom(sockfd, buf, 1024, 0, (struct sockaddr *)&clientaddr, &clientlen);
        if (size < 0){
            NSLog(@"Error in recvfrom");
            continue;
        }
        if (size < 1){
            NSLog(@"Packet must have at least 1 byte");
            continue;
        }
        NSLog(@"Server received %d bytes.", size);

        uint8_t command = buf[0];
        if (command == JAILBREAKD_COMMAND_ENTITLE){
            if (size < sizeof(struct JAILBREAKD_ENTITLE_PID)){
                NSLog(@"Error: ENTITLE packet is too small");
                continue;
            }
            struct JAILBREAKD_ENTITLE_PID *entitlePacket = (struct JAILBREAKD_ENTITLE_PID *)buf;
            NSLog(@"Entitle PID %d", entitlePacket->Pid);
            setcsflagsandplatformize(entitlePacket->Pid);
        }
        if (command == JAILBREAKD_COMMAND_ENTITLE_AND_SIGCONT){
            if (size < sizeof(struct JAILBREAKD_ENTITLE_PID_AND_SIGCONT)){
                NSLog(@"Error: ENTITLE_SIGCONT packet is too small");
                continue;
            }
            struct JAILBREAKD_ENTITLE_PID_AND_SIGCONT *entitleSIGCONTPacket = (struct JAILBREAKD_ENTITLE_PID_AND_SIGCONT *)buf;
            NSLog(@"Entitle+SIGCONT PID %d", entitleSIGCONTPacket->Pid);
            setcsflagsandplatformize(entitleSIGCONTPacket->Pid);
            kill(entitleSIGCONTPacket->Pid, SIGCONT);
        }
        if (command == JAILBREAKD_COMMAND_ENTITLE_PLATFORMIZE){
            if (size < sizeof(struct JAILBREAKD_ENTITLE_PLATFORMIZE_PID)){
                NSLog(@"Error: ENTITLE_PLATFORMIZE packet is too small");
                continue;
            }
            struct JAILBREAKD_ENTITLE_PLATFORMIZE_PID *entitlePlatformizePacket = (struct JAILBREAKD_ENTITLE_PLATFORMIZE_PID *)buf;
            NSLog(@"Entitle PID %d", entitlePlatformizePacket->EntitlePID);
            setcsflagsandplatformize(entitlePlatformizePacket->EntitlePID);
            NSLog(@"Platformize PID %d", entitlePlatformizePacket->PlatformizePID);
            setcsflagsandplatformize(entitlePlatformizePacket->PlatformizePID);
        }
        if (command == JAILBREAKD_COMMAND_ENTITLE_AND_SIGCONT_AFTER_DELAY){
            if (size < sizeof(struct JAILBREAKD_ENTITLE_PID_AND_SIGCONT)){
                NSLog(@"Error: ENTITLE_SIGCONT packet is too small");
                continue;
            }
            struct JAILBREAKD_ENTITLE_PID_AND_SIGCONT *entitleSIGCONTPacket = (struct JAILBREAKD_ENTITLE_PID_AND_SIGCONT *)buf;
            NSLog(@"Entitle+SIGCONT PID %d", entitleSIGCONTPacket->Pid);
            __block int PID = entitleSIGCONTPacket->Pid;
            dispatch_queue_t queue = dispatch_queue_create("org.coolstar.jailbreakd.delayqueue", NULL);
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 0.5 * NSEC_PER_SEC), queue, ^{
                setcsflagsandplatformize(PID);
                kill(PID, SIGCONT);
            });
            dispatch_release(queue);
        }
        if (command == JAILBREAKD_COMMAND_ENTITLE_AND_SIGCONT_FROM_XPCPROXY){
            if (size < sizeof(struct JAILBREAKD_ENTITLE_PID_AND_SIGCONT)){
                NSLog(@"Error: ENTITLE_SIGCONT packet is too small");
                continue;
            }
            struct JAILBREAKD_ENTITLE_PID_AND_SIGCONT *entitleSIGCONTPacket = (struct JAILBREAKD_ENTITLE_PID_AND_SIGCONT *)buf;
            NSLog(@"Entitle+SIGCONT PID %d", entitleSIGCONTPacket->Pid);
            __block int PID = entitleSIGCONTPacket->Pid;
            
            dispatch_queue_t queue = dispatch_queue_create("org.coolstar.jailbreakd.delayqueue", NULL);
            dispatch_async(queue, ^{
                char pathbuf[PROC_PIDPATHINFO_MAXSIZE];
                bzero(pathbuf, sizeof(pathbuf));
                
                NSLog(@"%@", @"Waiting to ensure it's not xpcproxy anymore...");
                int ret = proc_pidpath(PID, pathbuf, sizeof(pathbuf));
                while (ret > 0 && strcmp(pathbuf, "/usr/libexec/xpcproxy") == 0){
                    proc_pidpath(PID, pathbuf, sizeof(pathbuf));
                    usleep(100);
                }
                
                NSLog(@"%@",@"Continuing!");
                setcsflagsandplatformize(PID);
                kill(PID, SIGCONT);
            });
            dispatch_release(queue);
        }
        if (command == JAILBREAKD_COMMAND_DUMP_CRED){
            if (size < sizeof(struct JAILBREAKD_DUMP_CRED)){
                NSLog(@"Error: DUMP_CRED packet is too small");
                continue;
            }
            struct JAILBREAKD_DUMP_CRED *dumpCredPacket = (struct JAILBREAKD_DUMP_CRED *)buf;
            NSLog(@"Dump PID %d", dumpCredPacket->Pid);
            dumppid(dumpCredPacket->Pid);
        }
        if (command == JAILBREAKD_COMMAND_EXIT){
            NSLog(@"Got Exit Command! Goodbye!");
            term_kernel();
            term_kexecute();
            exit(0);
        }
    }

    /* Exit and clean up the child process. */
    _exit(0);
    return 0;
}

int main(int argc, char **argv, char **envp)
{
    char *endptr;
    kernel_base = strtoull(getenv("KernelBase"), &endptr, 16);
    // setpgid(getpid(), 0);

    int ret = runserver();
    exit(ret);
}

