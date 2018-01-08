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
#include "offsets.h"

#define SPECIAL_PORT TASK_BOOTSTRAP_PORT

static int32_t
send_port(mach_port_t remote_port, mach_port_t port)
{
    kern_return_t err;
    
    struct
    {
        mach_msg_header_t          header;
        mach_msg_body_t            body;
        mach_msg_port_descriptor_t task_port;
    } msg;
    
    msg.header.msgh_remote_port = remote_port;
    msg.header.msgh_local_port = MACH_PORT_NULL;
    msg.header.msgh_bits = MACH_MSGH_BITS (MACH_MSG_TYPE_COPY_SEND, 0) |
    MACH_MSGH_BITS_COMPLEX;
    msg.header.msgh_size = sizeof msg;
    
    msg.body.msgh_descriptor_count = 1;
    msg.task_port.name = port;
    msg.task_port.disposition = MACH_MSG_TYPE_COPY_SEND;
    msg.task_port.type = MACH_MSG_PORT_DESCRIPTOR;
    
    err = mach_msg_send(&msg.header);
    if(err != KERN_SUCCESS)
    {
        mach_error("Can't send mach msg\n", err);
        return (-1);
    }
    
    return (0);
}

static int32_t
recv_port(mach_port_t recv_port, mach_port_t *port)
{
    kern_return_t err;
    struct
    {
        mach_msg_header_t          header;
        mach_msg_body_t            body;
        mach_msg_port_descriptor_t task_port;
        mach_msg_trailer_t         trailer;
    } msg;
    
    err = mach_msg(&msg.header, MACH_RCV_MSG,
                   0, sizeof msg, recv_port,
                   MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
    if(err != KERN_SUCCESS)
    {
        mach_error("Can't recieve mach message\n", err);
        return (-1);
    }
    
    (*port) = msg.task_port.name;
    return 0;
}

static int32_t
setup_recv_port(mach_port_t *recv_port)
{
    kern_return_t       err;
    mach_port_t         port = MACH_PORT_NULL;
    err = mach_port_allocate(mach_task_self (),
                             MACH_PORT_RIGHT_RECEIVE, &port);
    if(err != KERN_SUCCESS)
    {
        mach_error("Can't allocate mach port\n", err);
        return (-1);
    }
    
    err = mach_port_insert_right(mach_task_self (),
                                 port,
                                 port,
                                 MACH_MSG_TYPE_MAKE_SEND);
    if(err != KERN_SUCCESS)
    {
        mach_error("Can't insert port right\n", err);
        return (-1);
    }
    
    (*recv_port) = port;
    return (0);
}

static int32_t
start(mach_port_t port, void *arg)
{
    
    return (0);
}

#define JAILBREAKD_COMMAND_ENTITLE 1
#define JAILBREAKD_COMMAND_ENTITLE_AND_SIGCONT 2
#define JAILBREAKD_COMMAND_ENTITLE_PLATFORMIZE 3
#define JAILBREAKD_COMMAND_ENTITLE_AND_SIGCONT_AFTER_DELAY 4
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

mach_port_t user_client;
uint64_t fake_client;

int runserver(){
    printf("[jailbreakd] Process Start!\n");

    int32_t rtrn = 0;
    kern_return_t err;
    mach_port_t pass_port;

    mach_port_t bootstrap_port = MACH_PORT_NULL;
    mach_port_t port = MACH_PORT_NULL;
    tfpzero = MACH_PORT_NULL;

    printf("[jailbreakd] Get Bootstrap Port!\n");
    
    /* In the child process grab the port passed by the parent. */
    err = task_get_special_port(mach_task_self(), SPECIAL_PORT, &bootstrap_port);
    if(err != KERN_SUCCESS)
    {
        mach_error("Can't get bootstrap port:\n", err);
        return (-1);
    }

    sleep(1);

    printf("[jailbreakd] Get Special Port!\n");
    
    /* In the child process grab the port passed by the parent. */
    err = task_get_special_port(mach_task_self(), SPECIAL_PORT, &pass_port);
    if(err != KERN_SUCCESS)
    {
        mach_error("Can't get special port:\n", err);
        return (-1);
    }
    
    printf("[jailbreakd] Create Mach Port!\n");
    /* Create a port with a send right. */
    if(setup_recv_port(&port) != 0)
    {
        printf("Can't setup mach port\n");
        return (-1);
    }
    
    printf("[jailbreakd] Send Mach Port!\n");
    /* Send port to parent. */
    rtrn = send_port(pass_port, port);
    if(rtrn < 0)
    {
        printf("Can't send port\n");
        return (-1);
    }
    
    /* Receive tfp0 from the parent. */
    rtrn = recv_port(port, &tfpzero);
    if(rtrn < 0)
    {
        printf("Can't receive task port\n");
        return (-1);
    }
    printf("[jailbreakd] Got tfp0: %u\n", tfpzero);
    
    /* Set the bootstrap port back to normal. */
    err = task_set_special_port(mach_task_self(), SPECIAL_PORT, bootstrap_port);
    if(err != KERN_SUCCESS)
    {
        mach_error("Can't set special port:\n", err);
        return (-1);
    }

    offsets_init();

    init_kernel(kernel_base, NULL);
    // Get the slide
    kernel_slide = kernel_base - 0xFFFFFFF007004000;
    printf("[jailbreakd] slide: 0x%016llx\n", kernel_slide);

    user_client = prepare_user_client();

    uint64_t cached_task_self_addr = 0;
    uint64_t task_self = task_self_addr();
    if (task_self == 0) {
        printf("unable to disclose address of our task port\n");
        sleep(10);
        exit(EXIT_FAILURE);
    }
    printf("our task port is at 0x%llx\n", task_self);

    // From v0rtex - get the IOSurfaceRootUserClient port, and then the address of the actual client, and vtable
    uint64_t IOSurfaceRootUserClient_port = find_port(user_client); // UserClients are just mach_ports, so we find its address
    printf("Found port: 0x%llx\n", IOSurfaceRootUserClient_port);

    uint64_t IOSurfaceRootUserClient_addr = rk64(IOSurfaceRootUserClient_port + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT)); // The UserClient itself (the C++ object) is at the kobject field
    printf("Found addr: 0x%llx\n", IOSurfaceRootUserClient_addr);

    uint64_t IOSurfaceRootUserClient_vtab = rk64(IOSurfaceRootUserClient_addr); // vtables in C++ are at *object
    printf("Found vtab: 0x%llx\n", IOSurfaceRootUserClient_vtab);

    // The aim is to create a fake client, with a fake vtable, and overwrite the existing client with the fake one
    // Once we do that, we can use IOConnectTrap6 to call functions in the kernel as the kernel

    
    // Create the vtable in the kernel memory, then copy the existing vtable into there
    uint64_t fake_vtable = kalloc(0x1000);
    printf("Created fake_vtable at %016llx\n", fake_vtable);
    
    for (int i = 0; i < 0x200; i++) {
        wk64(fake_vtable+i*8, rk64(IOSurfaceRootUserClient_vtab+i*8));
    }
    
    printf("Copied some of the vtable over\n");
    
    
    // Create the fake user client
    fake_client = kalloc(0x1000);
    printf("Created fake_client at %016llx\n", fake_client);
    
    for (int i = 0; i < 0x200; i++) {
        wk64(fake_client+i*8, rk64(IOSurfaceRootUserClient_addr+i*8));
    }
    
    printf("Copied the user client over\n");
    
    // Write our fake vtable into the fake user client
    wk64(fake_client, fake_vtable);
    
    // Replace the user client with ours
    wk64(IOSurfaceRootUserClient_port + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT), fake_client);
    
    // Now the userclient port we have will look into our fake user client rather than the old one
    
    // Replace IOUserClient::getExternalTrapForIndex with our ROP gadget (add x0, x0, #0x40; ret;)
    wk64(fake_vtable+8*0xB7, find_add_x0_x0_0x40_ret());
    
    printf("Wrote the `add x0, x0, #0x40; ret;` gadget over getExternalTrapForIndex\n");
    
    struct sockaddr_in serveraddr; /* server's addr */
    struct sockaddr_in clientaddr; /* client addr */

    printf("[jailbreakd] Running server...\n");
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0)
        printf("[jailbreakd] Error opening socket\n");
    int optval = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (const void *)&optval, sizeof(int));

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
    //serveraddr.sin_addr.s_addr = htonl(INADDR_ANY);
    bcopy((char *)server->h_addr,
          (char *)&serveraddr.sin_addr.s_addr, server->h_length);
    serveraddr.sin_port = htons((unsigned short)5);

    if (bind(sockfd, (struct sockaddr *)&serveraddr, sizeof(serveraddr)) < 0){
        printf("[jailbreakd] Error binding...\n");
        wk64(IOSurfaceRootUserClient_port + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT), IOSurfaceRootUserClient_addr);
        exit(-1);
    }
    printf("[jailbreakd] Server running!\n");

    char buf[1024];

    int clientlen = sizeof(clientaddr);
    while (1){
        bzero(buf, 1024);
        int size = recvfrom(sockfd, buf, 1024, 0, (struct sockaddr *)&clientaddr, &clientlen);
        if (size < 0){
            NSLog(@"Error in recvfrom");
        }
        NSLog(@"Server received %d bytes.", size);
        
        uint8_t command = buf[0];
        if (command == JAILBREAKD_COMMAND_ENTITLE){
            if (size < sizeof(struct JAILBREAKD_ENTITLE_PID)){
                NSLog(@"Error: ENTITLE packet is too small");
            }
            struct JAILBREAKD_ENTITLE_PID *entitlePacket = (struct JAILBREAKD_ENTITLE_PID *)buf;
            NSLog(@"Entitle PID %d\n", entitlePacket->Pid);
            setcsflagsandplatformize(entitlePacket->Pid);
        }
        if (command == JAILBREAKD_COMMAND_ENTITLE_AND_SIGCONT){
            if (size < sizeof(struct JAILBREAKD_ENTITLE_PID_AND_SIGCONT)){
                NSLog(@"Error: ENTITLE_SIGCONT packet is too small");
            }
            struct JAILBREAKD_ENTITLE_PID_AND_SIGCONT *entitleSIGCONTPacket = (struct JAILBREAKD_ENTITLE_PID_AND_SIGCONT *)buf;
            NSLog(@"Entitle+SIGCONT PID %d\n", entitleSIGCONTPacket->Pid);
            setcsflagsandplatformize(entitleSIGCONTPacket->Pid);
            kill(entitleSIGCONTPacket->Pid, SIGCONT);
        }
        if (command == JAILBREAKD_COMMAND_ENTITLE_PLATFORMIZE){
            if (size < sizeof(struct JAILBREAKD_ENTITLE_PLATFORMIZE_PID)){
                NSLog(@"Error: ENTITLE_PLATFORMIZE packet is too small");
            }
            struct JAILBREAKD_ENTITLE_PLATFORMIZE_PID *entitlePlatformizePacket = (struct JAILBREAKD_ENTITLE_PLATFORMIZE_PID *)buf;
            NSLog(@"Entitle PID %d\n", entitlePlatformizePacket->EntitlePID);
            setcsflagsandplatformize(entitlePlatformizePacket->EntitlePID);
            NSLog(@"Platformize PID %d\n", entitlePlatformizePacket->PlatformizePID);
            setcsflagsandplatformize(entitlePlatformizePacket->PlatformizePID);
        }
        if (command == JAILBREAKD_COMMAND_ENTITLE_AND_SIGCONT_AFTER_DELAY){
            if (size < sizeof(struct JAILBREAKD_ENTITLE_PID_AND_SIGCONT)){
                NSLog(@"Error: ENTITLE_SIGCONT packet is too small");
            }
            struct JAILBREAKD_ENTITLE_PID_AND_SIGCONT *entitleSIGCONTPacket = (struct JAILBREAKD_ENTITLE_PID_AND_SIGCONT *)buf;
            NSLog(@"Entitle+SIGCONT PID %d\n", entitleSIGCONTPacket->Pid);
            __block int PID = entitleSIGCONTPacket->Pid;
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 1 * NSEC_PER_SEC), dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0), ^{
                setcsflagsandplatformize(PID);
                kill(PID, SIGCONT);
            });
        }
        if (command == JAILBREAKD_COMMAND_DUMP_CRED){
            if (size < sizeof(struct JAILBREAKD_DUMP_CRED)){
                NSLog(@"Error: DUMP_CRED packet is too small");
            }
            struct JAILBREAKD_DUMP_CRED *dumpCredPacket = (struct JAILBREAKD_DUMP_CRED *)buf;
            NSLog(@"Dump PID %d\n", dumpCredPacket->Pid);
            dumppid(dumpCredPacket->Pid);
        }
        if (command == JAILBREAKD_COMMAND_EXIT){
            NSLog(@"Got Exit Command! Goodbye!");
            wk64(IOSurfaceRootUserClient_port + koffset(KSTRUCT_OFFSET_IPC_PORT_IP_KOBJECT), IOSurfaceRootUserClient_addr);
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
    kernel_base = strtoull(argv[1], &endptr, 10);
    setpgid(getpid(), 0);

    pid_t pid1 = fork();
    if(pid1 == 0)
    {
        pid_t pid2 = fork();
        if (pid2 == 0){
            unlink("/var/tmp/jailbreakd.pid");

            FILE *f = fopen("/var/tmp/jailbreakd.pid", "w");
            fprintf(f, "%d\n", getpid());
            fclose(f);

            int ret = runserver();
            exit(ret);
        } else {
            exit(0);
        }
    }
    else if(pid1 > 0)
    {
        int status;
        waitpid(pid1, &status, 0);
        return (0);
    }
    else
    {
        return (-1);
    }
    
    /* Exit and clean up the child process. */
    _exit(0);
    
    return (0);
}

