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

struct __attribute__((__packed__)) JAILBREAKD_ENTITLE_PID {
    uint8_t Command;
    int32_t Pid;
};

void send_packet(int command) {
    int sockfd;
    struct hostent *server;
    char buf[BUFSIZE];

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0)
        printf("ERROR opening socket\n");
    
        /* gethostbyname: get the server's DNS entry */
    server = gethostbyname(HOSTNAME);
    if (server == NULL) {
        fprintf(stderr,"ERROR, no such host as %s\n", HOSTNAME);
        return;
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
    sleep(1);
    setuid(0);
}
