#include <stdio.h>
#include <mach/mach.h>
#include <mach/error.h>
#include <mach/message.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "patchfinder64.h"
#include "kern_utils.h"

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

struct __attribute__((__packed__)) JAILBREAKD_PACKET {
    uint8_t Command;
};

struct __attribute__((__packed__)) JAILBREAKD_ENTITLE_PID {
    uint8_t Command;
    int32_t Pid;
};

mach_port_t tfpzero;
uint64_t kernel_base;

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

    usleep(3000 * 1000);

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
    
    /* Receive the real bootstrap port from the parent. */
    rtrn = recv_port(port, &tfpzero);
    if(rtrn < 0)
    {
        printf("Can't receive task port\n");
        return (-1);
    }
    printf("[jailbreakd] Got tfp0: %ld\n", tfpzero);
    
    /* Set the bootstrap port back to normal. */
    err = task_set_special_port(mach_task_self(), SPECIAL_PORT, bootstrap_port);
    if(err != KERN_SUCCESS)
    {
        mach_error("Can't set special port:\n", err);
        return (-1);
    }

    init_kernel(kernel_base, NULL);
    // Get the slide
    uint64_t slide = kernel_base - 0xFFFFFFF007004000;
    printf("[jailbreakd] slide: 0x%016llx\n", slide);
    
    struct sockaddr_in serveraddr; /* server's addr */
    struct sockaddr_in clientaddr; /* client addr */

    printf("[jailbreakd] Running server...\n");
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0)
        printf("[jailbreakd] Error opening socket\n");
    int optval = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (const void *)&optval, sizeof(int));

    bzero((char *) &serveraddr, sizeof(serveraddr));
    serveraddr.sin_family = AF_INET;
    serveraddr.sin_addr.s_addr = htonl(INADDR_ANY);
    serveraddr.sin_port = htons((unsigned short)2023);

    if (bind(sockfd, (struct sockaddr *)&serveraddr, sizeof(serveraddr)) < 0){
        printf("[jailbreakd] Error binding...\n");
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
            setcsflags(entitlePacket->Pid);
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

    NSLog(@"%@",@"Waiting for Empowerment...\n");
    usleep(3000 * 1000);
    NSLog(@"%@",@"Setting pguid...\n");
    setpgid(getpid(), 0);

    NSLog(@"%@",@"Forking once... (output will now be in syslog)\n");
    pid_t pid1 = fork();
    if(pid1 == 0)
    {
        NSLog(@"%@",@"Forking twice...");
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

