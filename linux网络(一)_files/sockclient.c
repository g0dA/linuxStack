/*==============================================================================

# Author:       lang  lyi4ng@gmail.com
# Filetype:     C source code
# Environment:  Linux & Archlinux
# Tool:         Vim & Gcc
# Date:         2019.10.14
# Descprition:  Randomly written code

================================================================================*/

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <sys/time.h>
#define MAXLEN 1024



int main(void)
{

	socklen_t len = 8;
	int a, val = 1;
	/*socket file description*/
	int sockfd,connc;
	char *message = "This is test\n",buf[MAXLEN];
	struct sockaddr_in6 servaddr;

	sockfd = socket(AF_INET6, SOCK_STREAM,0);
	if(sockfd == -1){
		perror("sock created");
		exit(-1);
	}

	/*set serverAddr default=0*/
	bzero(&servaddr, sizeof(servaddr));

	/*set serverAddr info*/
	servaddr.sin6_family = AF_INET6;
	servaddr.sin6_port = htons(9999);
	//servaddr.sin_addr.s_addr = inet_addr("0.0.0.0");
	inet_pton(AF_INET6,"127.0.0.1",&servaddr.sin6_addr);

	connc = connect(sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr));

	if(connc == -1){
		perror("connect error");
		exit(-1);
	}

	a = getsockopt(sockfd, IPPROTO_IP, IP_TOS, &val, &len);

	printf("default = %d\n",val);
	write(sockfd, message, strlen(message));

	read(sockfd, buf, MAXLEN);
	close(sockfd);

	return 0;

}

