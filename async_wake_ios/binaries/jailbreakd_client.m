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

struct __attribute__((__packed__)) JAILBREAKD_ENTITLE_PID {
    uint8_t Command;
    int32_t Pid;
};

int main(int argc, char **argv, char **envp) {
    int sockfd, portno, n;
    int serverlen;
    struct sockaddr_in serveraddr;
    struct hostent *server;
    char *hostname;
    char buf[BUFSIZE];
    
    hostname = "127.0.0.1";
    portno = 2023;
    
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

    struct JAILBREAKD_ENTITLE_PID entitlePacket;
    entitlePacket.Command = JAILBREAKD_COMMAND_ENTITLE;
    entitlePacket.Pid = atoi(argv[1]);

    memcpy(buf, &entitlePacket, sizeof(struct JAILBREAKD_ENTITLE_PID));
    
    serverlen = sizeof(serveraddr);
    n = sendto(sockfd, buf, sizeof(struct JAILBREAKD_ENTITLE_PID), 0, (const struct sockaddr *)&serveraddr, serverlen);
    if (n < 0)
        printf("Error in sendto\n");
    
	return 0;
}

// vim:ft=objc
