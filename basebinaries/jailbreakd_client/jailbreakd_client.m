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
#define JAILBREAKD_COMMAND_ROOTIFY 8
#define JAILBREAKD_COMMAND_ROOTIFY_AFTER_DELAY 9
#define JAILBREAKD_COMMAND_DUMP_CRED 7

struct __attribute__((__packed__)) JAILBREAKD_ENTITLE_PID {
    uint8_t Command;
    int32_t Pid;
};

void print_usage() {
    printf("Usage: \n");
    printf("jailbreakd_client <pid> <1 | 2 | 8>\n");
    printf("\t1 = entitle+platformize the target PID\n");
    printf("\t2 = entitle+platformize the target PID and subsequently sent SIGCONT\n");
    printf("\t8 = rootify the pid (su/sudo/setuid(0))\n");
}

int main(int argc, char **argv, char **envp) {
    if (argc < 3){
		print_usage();
        return 0;
    }
	if (argv[1] == "-h" || argv[1] == "--help") {
		print_usage();
		return 0;
	}
    int arg = atoi(argv[2]);
    if (arg != 1 && arg != 2 && arg != 7 && arg != 8 && arg != 9){
		print_usage();
        return 0;
    }

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

    struct JAILBREAKD_ENTITLE_PID entitlePacket;
    entitlePacket.Pid = atoi(argv[1]);

    if (arg == 1)
        entitlePacket.Command = JAILBREAKD_COMMAND_ENTITLE;
    else if (arg == 2)
        entitlePacket.Command = JAILBREAKD_COMMAND_PLATFORMIZE;
    else if (arg == 7)
        entitlePacket.Command = JAILBREAKD_COMMAND_DUMP_CRED;
	else if (arg == 8)
		entitlePacket.Command = JAILBREAKD_COMMAND_ROOTIFY;
	else if (arg == 9)
		entitlePacket.Command = JAILBREAKD_COMMAND_ROOTIFY_AFTER_DELAY;
	else {
		print_usage();
		return 0;
	}

    memcpy(buf, &entitlePacket, sizeof(struct JAILBREAKD_ENTITLE_PID));
    
    serverlen = sizeof(serveraddr);
    n = sendto(sockfd, buf, sizeof(struct JAILBREAKD_ENTITLE_PID), 0, (const struct sockaddr *)&serveraddr, serverlen);
    if (n < 0)
        printf("Error in sendto\n");
    
	return 0;
}

// vim:ft=objc
