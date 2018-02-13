#import <Foundation/Foundation.h>
#import <xpc/xpc.h>
#import <os/log.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <pthread.h>
#include "kexecute.h"
#include "kern_utils.h"
#include "patchfinder64.h"

#define CS_OPS_STATUS       0   /* return status */

#define CS_GET_TASK_ALLOW    0x0000004    /* has get-task-allow entitlement */
#define CS_INSTALLER        0x0000008    /* has installer entitlement */

#define    CS_HARD            0x0000100    /* don't load invalid pages */
#define    CS_KILL            0x0000200    /* kill process if it becomes invalid */
#define CS_RESTRICT        0x0000800    /* tell dyld to treat restricted */

#define CS_PLATFORM_BINARY    0x4000000    /* this is a platform binary */

#define CS_DEBUGGED         0x10000000  /* process is currently or has previously been debugged and allowed to run with invalid pages */

int csops(pid_t pid, unsigned int  ops, void * useraddr, size_t usersize);

#define PROC_PIDPATHINFO_MAXSIZE  (1024)
int proc_pidpath(pid_t pid, void *buffer, uint32_t buffersize);

#define JAILBREAKD_COMMAND_ENTITLE_AND_SIGCONT 2
struct __attribute__((__packed__)) JAILBREAKD_ENTITLE_PID_AND_SIGCONT {
    uint8_t Command;
    int32_t Pid;
};

#define MEMORYSTATUS_CMD_SET_JETSAM_TASK_LIMIT 6
int memorystatus_control(uint32_t command, int32_t pid, uint32_t flags, void *buffer, size_t buffersize);

int remove_memory_limit(void) {
    // daemons run under launchd have a very stingy memory limit by default, we need
    // quite a bit more for patchfinder so disable it here
    // (note that we need the com.apple.private.memorystatus entitlement to do so)
    pid_t my_pid = getpid();
    return memorystatus_control(MEMORYSTATUS_CMD_SET_JETSAM_TASK_LIMIT, my_pid, 0, NULL, 0);
}

mach_port_t tfpzero;
uint64_t kernel_base;
uint64_t kernel_slide;
extern unsigned offsetof_ip_kobject;

/*
    The jailbreakd XPC protocol request:
    {
        "action": string, see below
        "pid": int64
        "flags": uint64, see below, only for entp
    }

    The reply:
    {
        "action": string from request
        "pid": int64 from request
        "result": uint64, 1 for success or 0 for failure
    }

    Bugs:
    - the exit command doesn't reply
    - failure currently isn't implemented so result is always 1
*/

const char *JAILBREAKD_ACTION_ENTITLE = "entp";
const char *JAILBREAKD_ACTION_FIX_SETUID = "suid";
const char *JAILBREAKD_ACTION_PING = "ping";
const char *JAILBREAKD_ACTION_EXIT = "exit";

/* Flags for entp command. Any combination or none can be specified. */
/* Wait for xpcproxy to exec before continuing */
#define FLAG_WAIT_EXEC   (1 << 5)
/* Wait for 0.5 sec after acting */
#define FLAG_DELAY       (1 << 4)
/* Send SIGCONT after acting */
#define FLAG_SIGCONT     (1 << 3)
/* Set sandbox exception */
#define FLAG_SANDBOX     (1 << 2)
/* Set platform binary flag */
#define FLAG_PLATFORMIZE (1 << 1)
/* Set basic entitlements */
#define FLAG_ENTITLE     (1)

/* bits 0-3 */
#define FLAG_KERN_ACTIONS_MASK (0x07)
#define FLAG_WAITING_MASK (0x30)

/* Convert the bitset specified above to a string like "eps--X" */
static void flags_to_string(uint64_t flags, char *flgstr) {
    const char *set = "epsCDX";
    for (int i = 0; i < 6; ++i) {
        if (flags & (1 << i)) {
            flgstr[i] = set[i];
        } else {
            flgstr[i] = '-';
        }
    }
}

static void do_entp_stuff_with_pid(uint64_t stuff, pid_t pid, void(^finish)(uint64_t stuff, pid_t pid)) {
    void (^actually_do_what_were_supposed_to)(void) = ^{
        /* FIXME: respect flags */
        uint32_t flags;
        csops(pid, CS_OPS_STATUS, &flags, 0);
        fprintf(stderr, "Waiting for CSFlags to reset for PID %d...\n", pid);
        
        int tries = 0;
        while ((flags & (CS_PLATFORM_BINARY | CS_INSTALLER | CS_GET_TASK_ALLOW | CS_DEBUGGED)) != 0 &&
               (flags & (CS_RESTRICT | CS_HARD | CS_KILL)) == 0 &&
               tries < 5000){
            csops(pid, CS_OPS_STATUS, &flags, 0);
            usleep(100);
            tries++;
        }
        
        if (tries >= 5000){
            fprintf(stderr, "Warning: CSFlag timer timed out for PID %d\n", pid);
        }
        
        setcsflagsandplatformize(pid);
        
        csops(pid, CS_OPS_STATUS, &flags, 0);
        fprintf(stderr,"CSFlags for PID %d: 0x%x\n", pid, flags);
        
        if (stuff & FLAG_SIGCONT) {
            fprintf(stderr,"Sending SIGCONT to %d\n", pid);
            kill(pid, SIGCONT);
        }

        /* see below! */
        if ((stuff & FLAG_WAIT_EXEC) == 0) {
            dispatch_async(dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0), ^{
                finish(stuff, pid);
            });
        }
    };

    /* skip waitgroup nonsense if we can */
    if ((stuff & FLAG_WAITING_MASK) == 0) {
        dispatch_async(dispatch_get_main_queue(), ^{
            actually_do_what_were_supposed_to();
        });
        return;
    }

    /* we'll wait on both conditions at the same time */
    dispatch_group_t waitgroup = dispatch_group_create();
    if (stuff & FLAG_WAIT_EXEC) {
        /* it's safe to get xpcproxy's path here --
           pspawn_payload won't exec until later */
        // char *cmp_path = malloc(PROC_PIDPATHINFO_MAXSIZE);
        // memset(cmp_path, 0, PROC_PIDPATHINFO_MAXSIZE);
        // proc_pidpath(pid, cmp_path, PROC_PIDPATHINFO_MAXSIZE);

        dispatch_group_async(waitgroup, dispatch_get_main_queue(), ^{
            char pathbuf[PROC_PIDPATHINFO_MAXSIZE] = {0};

            fprintf(stderr,"Waiting to ensure it's not xpcproxy anymore...\n");
            int ret = proc_pidpath(pid, pathbuf, sizeof(pathbuf));
            while (ret > 0 && strcmp(pathbuf, "/usr/libexec/xpcproxy") == 0){
                ret = proc_pidpath(pid, pathbuf, sizeof(pathbuf));
                if (strcmp(pathbuf, "/usr/libexec/xpcproxy") != 0)
                    fprintf(stderr,"proc_pidpath %d -> %d %s\n", pid, ret, pathbuf);
                usleep(100);
            }
            // free(cmp_path);
        });

        /* hack: the pspawn payload won't exec until we reply, so just for
           FLAG_XPCPROXY, we'll pretend the operation completed before it actually does */
        dispatch_async(dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0), ^{
            finish(stuff, pid);
        });
    }

    if (stuff & FLAG_DELAY) {
        dispatch_group_enter(waitgroup);
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 0.5 * NSEC_PER_SEC), dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0), ^{
            dispatch_group_leave(waitgroup);
        });
    }

    dispatch_group_notify(waitgroup, dispatch_get_main_queue(), actually_do_what_were_supposed_to);
    dispatch_release(waitgroup);
}

static void do_suid_with_pid(pid_t pid, void(^finish)(pid_t pid)) {
    dispatch_async(dispatch_get_main_queue(), ^{
        fixupsetuid(pid);
        finish(pid);
    });
}

static void jailbreakd_handle_xpc_connection(xpc_connection_t who) {
    xpc_connection_set_event_handler(who, ^(xpc_object_t msg) {
        xpc_type_t type = xpc_get_type(msg);
        if (type == XPC_TYPE_ERROR) {
            fprintf(stderr,"jailbreakd: connection error %s\n", xpc_dictionary_get_string(msg, XPC_ERROR_KEY_DESCRIPTION));
            return;
        }

        xpc_connection_t peer = xpc_dictionary_get_remote_connection(msg);

        char *desc = xpc_copy_description(msg);
        fprintf(stderr,"jailbreakd: received object: %s\n", desc);
        free(desc);

        const char *action = xpc_dictionary_get_string(msg, "action");
        if (!action) {
            char *desc = xpc_copy_description(msg);
            fprintf(stderr,"jailbreakd: received message from pid %d with no action: %s\n",
                xpc_connection_get_pid(peer),
                desc);
            free(desc);
            xpc_connection_cancel(peer);
            return;
        }

        // TODO: use csops to restrict custom pid to entitlement?
        pid_t reqpid = (pid_t)xpc_dictionary_get_int64(msg, "pid");
        if (reqpid == 0) {
            reqpid = xpc_connection_get_pid(peer);
        }

        xpc_retain(msg);
        if (!strcmp(action, JAILBREAKD_ACTION_ENTITLE)) {
            uint64_t flags = xpc_dictionary_get_uint64(msg, "flags");
            do_entp_stuff_with_pid(flags, reqpid, ^(uint64_t stuff, pid_t pid) {
                char flgstr[7] = {0};
                flags_to_string(flags, flgstr);
                fprintf(stderr,"jailbreakd: entitle operations: %s complete for pid %d\n", flgstr, reqpid);

                xpc_object_t reply = xpc_dictionary_create_reply(msg);
                if (!reply) {
                    fprintf(stderr,"jailbreakd: can't create reply. did the other end hang up too soon??\n");
                    xpc_release(msg);
                    return;
                }

                xpc_dictionary_set_string(reply, "action", action);
                xpc_dictionary_set_uint64(reply, "flags", flags);
                xpc_dictionary_set_uint64(reply, "result", 1);

                xpc_connection_send_message(xpc_dictionary_get_remote_connection(msg), reply);
                xpc_release(reply);
                xpc_release(msg);
            });
        } else if (!strcmp(action, JAILBREAKD_ACTION_FIX_SETUID)) {
            do_suid_with_pid(reqpid, ^(pid_t pid) {
                fprintf(stderr,"jailbreakd: suid complete for pid %d\n", reqpid);

                xpc_object_t reply = xpc_dictionary_create_reply(msg);
                if (!reply) {
                    fprintf(stderr,"jailbreakd: can't create reply. did the other end hang up too soon??\n");
                    xpc_release(msg);
                    return;
                }

                xpc_dictionary_set_string(reply, "action", action);
                xpc_dictionary_set_uint64(reply, "result", 1);

                xpc_connection_send_message(xpc_dictionary_get_remote_connection(msg), reply);
                xpc_release(reply);
                xpc_release(msg);
            });
        } else if (!strcmp(action, JAILBREAKD_ACTION_PING)) {
            fprintf(stderr,"jailbreakd: ping complete for pid %d\n", reqpid);
            xpc_object_t reply = xpc_dictionary_create_reply(msg);
            if (!reply) {
                fprintf(stderr,"jailbreakd: can't create reply. did the other end hang up too soon??\n");
                xpc_release(msg);
                return;
            }

            xpc_dictionary_set_string(reply, "action", action);
            xpc_dictionary_set_uint64(reply, "result", 1);

            xpc_connection_send_message(xpc_dictionary_get_remote_connection(msg), reply);
            xpc_release(reply);
            xpc_release(msg);
        } else if (!strcmp(action, JAILBREAKD_ACTION_EXIT)) {
            xpc_release(msg);

            fprintf(stderr,"jailbreakd: exiting for pid %d!\n", reqpid);

            term_kexecute();
            exit(0);
        } else {
            fprintf(stderr,"jailbreakd: invalid action! %s\n", action);
            xpc_release(msg);
            xpc_connection_cancel(peer);
        }
    });
    xpc_connection_resume(who);
}

struct InitThreadArg {
    int clientFd;
    struct sockaddr_in clientAddr;
    int threadNum;
};

int threadCount = 0;

void *initThread(struct InitThreadArg *args){
    int yes = 1;
    setsockopt(args->clientFd, SOL_SOCKET, SO_KEEPALIVE, &yes, sizeof(int));
    
    int alive = 1;
    setsockopt(args->clientFd, IPPROTO_TCP, TCP_KEEPALIVE, &alive, sizeof(int));
    
    int set = 1;
    setsockopt(args->clientFd, SOL_SOCKET, SO_NOSIGPIPE, (void *)&set, sizeof(int));
    
    char buf[1024];
    while (true){
        int bytesRead = recv(args->clientFd, buf, 1024, 0);
        fprintf(stderr,"Bytes Read: %d\n", bytesRead);
        if (bytesRead){
            int bytesProcessed = 0;
            while (bytesProcessed < bytesRead){
                if (bytesRead - bytesProcessed >= sizeof(struct JAILBREAKD_ENTITLE_PID_AND_SIGCONT)){
                    struct JAILBREAKD_ENTITLE_PID_AND_SIGCONT *clientMessage = (struct JAILBREAKD_ENTITLE_PID_AND_SIGCONT*)(buf + bytesProcessed);
                    if (clientMessage->Command != JAILBREAKD_COMMAND_ENTITLE_AND_SIGCONT){
                        fprintf(stderr,"Invalid command\n");
                    }
                    if (clientMessage->Command == JAILBREAKD_COMMAND_ENTITLE_AND_SIGCONT){
                        fprintf(stderr,"Got Request to Entitle PID %u\n", clientMessage->Pid);
                        
                        setcsflagsandplatformize(clientMessage->Pid);
                        kill(clientMessage->Pid, SIGCONT);
                    }
                }
                bytesProcessed += sizeof(struct JAILBREAKD_ENTITLE_PID_AND_SIGCONT);
            }
        } else {
            fprintf(stderr,"Client disconnected\n");
            break;
        }
    }
    threadCount--;
    return NULL;
}

bool isXPCInit = false;
bool isTCPInit = false;

void* thd_func(void* arg){
    fprintf(stderr,"In a new thread!\n");
    struct sockaddr_in serveraddr; /* server's addr */
    struct sockaddr_in clientaddr; /* client addr */
    
    fprintf(stderr,"[jailbreakd] Running server...\n");
    int listenFd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listenFd < 0)
        fprintf(stderr,"[jailbreakd] Error opening socket\n");
    int optval = 1;
    setsockopt(listenFd, SOL_SOCKET, SO_REUSEADDR, (const void *)&optval, sizeof(int));
    
    struct hostent *server;
    char *hostname = "127.0.0.1";
    /* gethostbyname: get the server's DNS entry */
    server = gethostbyname(hostname);
    if (server == NULL) {
        fprintf(stderr,"[jailbreakd] ERROR, no such host as %s\n", hostname);
        exit(0);
    }
    
    bzero((char *) &serveraddr, sizeof(serveraddr));
    serveraddr.sin_family = AF_INET;
    bcopy((char *)server->h_addr, (char *)&serveraddr.sin_addr.s_addr, server->h_length);
    serveraddr.sin_port = htons((unsigned short)5);
    
    if (bind(listenFd, (struct sockaddr *)&serveraddr, sizeof(serveraddr)) < 0){
        fprintf(stderr,"[jailbreakd] Error binding...\n");
        exit(-1);
    }
    
    listen(listenFd, 5);
    
    char buf[1024];
    
    socklen_t clientlen = sizeof(clientaddr);
    
    isTCPInit = true;
    
    if (isXPCInit && isTCPInit){
        int fd = open("/tmp/jailbreakd.pid", O_WRONLY | O_CREAT, 0600);
        char mmmm[8] = {0};
        int sz = snprintf(mmmm, 8, "%d", getpid());
        write(fd, mmmm, sz);
        close(fd);
        
        fprintf(stderr,"jailbreakd: dumped pid\n");
    }
    
    
    while (true){
        int clientFd = accept(listenFd, (struct sockaddr *)&clientaddr, &clientlen);
        
        if (clientFd < 0){
            fprintf(stderr,"Unable to accept\n");
            return NULL;
        }
        
        pthread_t thread;
        struct InitThreadArg args;
        args.clientFd = clientFd;
        args.clientAddr = clientaddr;
        args.threadNum = threadCount;
        
        int err = pthread_create(&thread, NULL, (void *(*)(void *))&initThread, &args);
        if (err != 0){
            fprintf(stderr,"Unable to create thread\n");
            pthread_detach(thread);
        }
        
        threadCount++;
    }
}

int main(int argc, char **argv, char **envp) {
    fprintf(stderr,"jailbreakd: start\n");

    unlink("/tmp/jailbreakd.pid");

    kernel_base = strtoull(getenv("KernelBase"), NULL, 16);
    remove_memory_limit();

    kern_return_t err = host_get_special_port(mach_host_self(), HOST_LOCAL_NODE, 4, &tfpzero);
    if (err != KERN_SUCCESS) {
        fprintf(stderr,"host_get_special_port 4: %s\n", mach_error_string(err));
        return 5;
    }

    init_kernel(kernel_base, NULL);
    // Get the slide
    kernel_slide = kernel_base - 0xFFFFFFF007004000;
    fprintf(stderr,"jailbreakd: slide: 0x%016llx\n", kernel_slide);

    // prime offset caches
    find_allproc();
    find_add_x0_x0_0x40_ret();
    find_OSBoolean_True();
    find_OSBoolean_False();
    find_zone_map_ref();
    find_osunserializexml();
    find_smalloc();
    init_kexecute();

    term_kernel();

    pthread_t thd;
    pthread_create(&thd, NULL, thd_func, NULL);
    pthread_detach(thd);
    
    @autoreleasepool {
        /* About concurrency:
             kernel calls run on the main thread ONLY. Everything else can run in dispatch global queues. */
        xpc_connection_t connection = xpc_connection_create_mach_service(
            "com.apple.uikit.viewservice.xxx.dainsleif.xpc",
            NULL, XPC_CONNECTION_MACH_SERVICE_LISTENER);
        if (!connection) {
            fprintf(stderr,"jailbreakd: no XPC service\n");
            return 0;
        }

        // Configure event handler
        xpc_connection_set_event_handler(connection, ^(xpc_object_t object) {
            xpc_type_t type = xpc_get_type(object);
            if (type == XPC_TYPE_CONNECTION) {
                fprintf(stderr,"jailbreakd: received XPC connection!\n");
                jailbreakd_handle_xpc_connection(object);
            } else if (type == XPC_TYPE_ERROR) {
                fprintf(stderr,"jailbreakd: XPC error in listener: %s\n", xpc_dictionary_get_string(object, XPC_ERROR_KEY_DESCRIPTION));
            }
        });

        // Make connection live
        xpc_connection_resume(connection);
        fprintf(stderr,"it never fails to strike its target, and the wounds it causes do not heal\n");
        fprintf(stderr,"in other words, XPC is online\n");

        isXPCInit = true;
        
        if (isXPCInit && isTCPInit){
            int fd = open("/tmp/jailbreakd.pid", O_WRONLY | O_CREAT, 0600);
            char mmmm[8] = {0};
            int sz = snprintf(mmmm, 8, "%d", getpid());
            write(fd, mmmm, sz);
            close(fd);
            
            fprintf(stderr,"jailbreakd: dumped pid\n");
        }
        
        dispatch_main();
    }

    return EXIT_FAILURE;
}
