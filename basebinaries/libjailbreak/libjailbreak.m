//
//  libjailbreak.m
//  libjailbreak
//
//  Created by Jamie Bishop on 29/01/2018.
//  Copyright © 2018 Electra Team. All rights reserved.
//

#import "libjailbreak.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#define BUFSIZE 1024

#define JAILBREAKD_COMMAND_ENTITLE 1
#define JAILBREAKD_COMMAND_PLATFORMIZE 2
#define JAILBREAKD_COMMAND_FIXUP_SETUID 6

struct __attribute__((__packed__)) JAILBREAKD_ENTITLE_PID {
    uint8_t Command;
    int32_t Pid;
};

int jailbreakd_sockfd = -1;
struct sockaddr_in jailbreakd_serveraddr;
int jailbreakd_serverlen;
struct hostent *jailbreakd_server;

void open_socket() {
    char *hostname = "127.0.0.1";
    int portno = 5;
    
    jailbreakd_sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (jailbreakd_sockfd < 0)
        printf("ERROR opening socket\n");
    
    /* gethostbyname: get the server's DNS entry */
    jailbreakd_server = gethostbyname(hostname);
    if (jailbreakd_server == NULL) {
        fprintf(stderr,"ERROR, no such host as %s\n", hostname);
        return;
    }
    
    /* build the server's Internet address */
    bzero((char *) &jailbreakd_serveraddr, sizeof(jailbreakd_serveraddr));
    jailbreakd_serveraddr.sin_family = AF_INET;
    bcopy((char *)jailbreakd_server->h_addr,
          (char *)&jailbreakd_serveraddr.sin_addr.s_addr, jailbreakd_server->h_length);
    jailbreakd_serveraddr.sin_port = htons(portno);
    
    jailbreakd_serverlen = sizeof(jailbreakd_serveraddr);
}

void close_socket() {
    close(jailbreakd_sockfd);
    jailbreakd_sockfd = -1;
}

void call_jailbreakd(pid_t pid, int command) {
    if (jailbreakd_sockfd == -1)
        open_socket();
    
    char buf[BUFSIZE];
    
    /* get a message from the user */
    bzero(buf, BUFSIZE);
    
    struct JAILBREAKD_ENTITLE_PID packet;
    packet.Command = command;
    packet.Pid = pid;
    
    memcpy(buf, &packet, sizeof(packet));
    
    int rv = sendto(jailbreakd_sockfd, buf, sizeof(struct JAILBREAKD_ENTITLE_PID), 0, (const struct sockaddr *)&jailbreakd_serveraddr, jailbreakd_serverlen);
    if (rv < 0)
        printf("Error in sendto\n");
    close_socket();
}

void jb_entitle(pid_t pid) {
    call_jailbreakd(pid, JAILBREAKD_COMMAND_ENTITLE);
}

void jb_platformize(pid_t pid) {
    call_jailbreakd(pid, JAILBREAKD_COMMAND_PLATFORMIZE);
}

void jb_fix_setuid(pid_t pid) {
    call_jailbreakd(pid, JAILBREAKD_COMMAND_FIXUP_SETUID);
    // hack af, but to remove this we're waiting on XPC
    sleep(1);
    setuid(0);
}
