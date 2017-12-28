//
//  jailbreakd.c
//  async_wake_ios
//
//  Created by CoolStar on 12/25/17.
//  Copyright © 2017 Ian Beer. All rights reserved.
//

#include <stdio.h>
#include <stdlib.h>
#include <mach/mach.h>
#include <mach/error.h>
#include <mach/message.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#import <Foundation/Foundation.h>
#include <spawn.h>

int file_exist(char *filename);

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

int startprog(uint64_t kern_ucred, bool wait, const char *prog, const char* args[], const char* envp[]);

int start_jailbreakd(uint64_t kern_ucred, mach_port_t *pass_port, mach_port_t task_for_pid0, uint64_t kernel_base)
{
    pid_t pid = 0;
    int32_t rtrn = 0;
    kern_return_t err;
    mach_port_t special_port = MACH_PORT_NULL;
    
    /* Allocate the mach port. */
    if(setup_recv_port(pass_port) != 0)
    {
        printf("Can't setup mach port\n");
        return (-1);
    }
    
    unlink("/var/tmp/jailbreakd.pid");
    
    pid_t pd;
    
    NSString *kernel_base_str = [NSString stringWithFormat:@"%llu",kernel_base];
    posix_spawn(&pd, "/bootstrap/jailbreakd", NULL, NULL, (char **)&(char*[]){"jailbreakd", (char *)[kernel_base_str UTF8String], NULL}, NULL);
    
    printf("Waiting for jailbreakd...\n");
    
    while (!file_exist("/var/tmp/jailbreakd.pid")){
        usleep(300 * 1000);
    }
    
    usleep(100 * 1000);
    
    FILE *f = fopen("/var/tmp/jailbreakd.pid", "r");
    fscanf(f, "%d", &pid);
    fclose(f);
    
    printf("Found jailbreakd at PID %d. Continuing...\n", pid);
    
    task_t childPidTask;
    err = task_for_pid(mach_task_self(), pid, &childPidTask);
    if(err != KERN_SUCCESS)
    {
        mach_error("Can't get task for child pid:\n", err);
        return (-1);
    }
    printf("Got TFP jailbreakd PID (%d %u)\n", pid, childPidTask);
    err = task_set_special_port(childPidTask, SPECIAL_PORT, (*pass_port));
    if(err != KERN_SUCCESS)
    {
        mach_error("Can't set special port:\n", err);
        return (-1);
    }
    printf("Set jailbreakd Special Port\n");
    
    mach_port_t child_port = MACH_PORT_NULL;
    
    /* Grab the child's recv port. */
    rtrn = recv_port((*pass_port), &child_port);
    if(rtrn < 0)
    {
        printf("Can't recv port\n");
        return (-1);
    }
    
    /* Send the child the task port. */
    printf("Sent Task port: %ld\n", task_for_pid0);
    rtrn = send_port(child_port, task_for_pid0);
    if(rtrn < 0)
    {
        printf("Can't send task port\n");
        return (-1);
    }
    
    return 0;
}
