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
#define HOSTNAME "127.0.0.1"

#define JAILBREAKD_COMMAND_ENTITLE 1
#define JAILBREAKD_COMMAND_PLATFORMIZE 2
#define JAILBREAKD_COMMAND_FIXUP_SETUID 6

// Global socket variable
static int sockfd;
static struct hostent *server;

void send_packet(int command) {
    char buf[BUFSIZE];
    
    if (sockfd < 0) {
        // No socket
        sockfd = socket(AF_INET, SOCK_DGRAM, 0);
        if (sockfd < 0)
            printf("ERROR opening socket\n");
    }
    
    if (server == NULL) {
        /* gethostbyname: get the server's DNS entry */
        server = gethostbyname(HOSTNAME);
        if (server == NULL) {
            fprintf(stderr,"ERROR, no such host as %s\n", HOSTNAME);
            return;
        }
    }
    
    /* build the server's Internet address */
    struct sockaddr_in serveraddr;
    bzero((char *) &serveraddr, sizeof(serveraddr));
    serveraddr.sin_family = AF_INET;
    bcopy((char *)server->h_addr,
          (char *)&serveraddr.sin_addr.s_addr, server->h_length);
    serveraddr.sin_port = htons(5);
    
    bzero(buf, BUFSIZE);
    
    struct JAILBREAKD_ENTITLE_PID entitlePacket;
    entitlePacket.Pid = getpid();
    entitlePacket.Command = command;
    
    memcpy(buf, &entitlePacket, sizeof(struct JAILBREAKD_ENTITLE_PID));
    
    ssize_t rv = sendto(sockfd, buf, sizeof(struct JAILBREAKD_ENTITLE_PID), 0, (const struct sockaddr *)&serveraddr, sizeof(serveraddr));
    if (rv < 0)
        printf("Error in sendto\n");
    return;
}

void entitle(void) {
    send_packet(JAILBREAKD_COMMAND_ENTITLE);
}

void platformize(void) {
    send_packet(JAILBREAKD_COMMAND_PLATFORMIZE);
}

void fix_setuid(void) {
    send_packet(JAILBREAKD_COMMAND_FIXUP_SETUID);
    setuid(0);
}
