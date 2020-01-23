/*==============================================================================

# Author:       lang  lyi4ng@gmail.com
# Filetype:     C source code
# Environment:  Linux & Archlinux
# Tool:         Vim & Gcc
# Date:         2019.12.17
# Descprition:  Create tun/tap veth

================================================================================*/

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <netinet/ip.h>
#include <linux/udp.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>

int tun_create(char *dev, int flags)
{
	struct ifreq ifr;
	int fd, err;
	
	if ((fd = open("/dev/net/tun", O_RDWR)) < 0) {
		perror("Opening /dev/net/tun");
		return fd;
	}
	
	memset(&ifr, 0, sizeof(ifr));

	ifr.ifr_flags = flags;

	if (*dev)
		strncpy(ifr.ifr_name, dev, IFNAMSIZ);

	if ((err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0) {
		perror("ioctl(TUNSETIFF)");
		close(fd);
		return err;
	}

	strcpy(dev, ifr.ifr_name);

	return fd;	
}


struct dnshdr {
	__u16 id;
	__u16 flag;
	__u16 ques;
	__u16 as_rrs;
	__u16 au_rrs;
	__u16 ad_rrs;
	
};

//伪首部UDP
struct vudphdr {
	__be32 saddr;
	__be32 daddr;
	__u8 zeroadd;
	__u8 protocol;
	__u16 size;
	char udppacket[BUFSIZ];
};

uint16_t calc_cksm(void *pkt, int len)
{
    uint16_t *buf = (uint16_t*)pkt;
    uint32_t cksm = 0;
    while(len > 1)
    {
        cksm += *buf++;
        cksm = (cksm >> 16) + (cksm & 0xffff);
        len -= 2;
    }
    if(len)
    {
        cksm += *((uint8_t*)buf);
        cksm = (cksm >> 16) + (cksm & 0xffff);
    }
    return (uint16_t)((~cksm) & 0xffff);
}

int main(int argc, char *argv[])
{

	char *queries, buffer[BUFSIZ], veth_name[IFNAMSIZ] = "tunveth1";

	int i, tun_fd, nread, nwrite, NAMESIZE, DNSQUERYSIZE;

	struct iphdr *iph;
	struct udphdr *udph;
	struct dnshdr *dnsh;

	struct in_addr saddr, daddr;	

	struct vudphdr vudph;

	tun_fd = tun_create(veth_name, IFF_TUN | IFF_NO_PI);

	

	if (tun_fd < 0) {
		perror("Creating interface");
		exit(1);
	}

	while(1) {
		memset(buffer, 0, sizeof(buffer));
		nread = read(tun_fd, buffer, sizeof(buffer));
		if (nread < 0) {
			perror("Reading from interface");
			close(tun_fd);
			exit(1);
		}
		
		iph = (struct iphdr*)buffer;
		


		if (iph->version == 4 && iph->protocol == 17) {		

			udph = (struct udphdr*)(buffer + sizeof(struct iphdr));

			if (udph->dest == 0x3500) {
				printf("\nRead %d bytes from device %s\n", nread, veth_name);
				memcpy(&saddr.s_addr, &iph->saddr, 4);
				memcpy(&daddr.s_addr, &iph->daddr, 4);
				printf("Source host:%s\n", inet_ntoa(saddr));
				printf("Dest host:%s\n", inet_ntoa(daddr));
				
				
				dnsh = (struct dnshdr*)(buffer + sizeof(struct iphdr) + sizeof(struct udphdr));
				//判断需要劫持的域名	
				queries = buffer + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct dnshdr);
				NAMESIZE = nread - 2 - (sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(struct dnshdr));
				char queryname[NAMESIZE];
				memcpy(queryname, queries, NAMESIZE);
				char checkname[] = {0x07, 0x74, 0x75, 0x6e, 0x76, 0x65, 0x74, 0x68, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01}; 
				//char checkname[] = { 0x05, 0x62, 0x61, 0x69, 0x64, 0x75, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01 };
				//需要比对的值: 0774756e7665746803636f6d00
				if (memcmp(checkname, queryname, 13) == 0 ) {
					char answers[] = { 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0xd4, 0x00, 0x04, 0x63, 0x01, 0x01, 0x19 };
					//添加DNS answer
					memcpy((buffer + nread), &answers, sizeof(answers));

					iph->check = 0x0000;
					//构建返回ip帧
					iph->tot_len = htons(ntohs(iph->tot_len) + sizeof(answers));
					//printf("Edited tot_len = %d\n", ntohs(iph->tot_len));
					iph->id = htons(23333);
					iph->frag_off = 0x0000;
					iph->ttl = iph->ttl - 0x1;
					__be32 *addr_buf;
					
					addr_buf = iph->saddr;
					iph->saddr = iph->daddr;
					iph->daddr = addr_buf;
			
					iph->check = calc_cksm(iph, sizeof(struct iphdr));

					//构造返回udp帧
					__be16 *port_buf;

					udph->check = 0x0000;
					port_buf = udph->dest;
					udph->dest = udph->source;
					udph->source = port_buf;
					udph->len = htons(ntohs(udph->len) + sizeof(answers));
				
					//构造伪头部 32bit源地址/目的地址 + 8bit补零 + 8bit协议号(0x11) + 16bitUDP报文长度
					
					memcpy(&(vudph.saddr), &(iph->saddr), sizeof(__be32));
					memcpy(&(vudph.daddr), &(iph->daddr), sizeof(__be32));
					vudph.zeroadd = 0x00;
					vudph.protocol = 0x11;
					memcpy(&(vudph.size), &(udph->len), sizeof(__u16));
					
					memset(&(vudph.udppacket), 0, BUFSIZ);

					dnsh->as_rrs = 0x0100;
					dnsh->flag = 0x8081;
					
					memcpy(&(vudph.udppacket), udph, ntohs(udph->len));

					udph->check = calc_cksm((char*)&vudph, sizeof(vudph));
					

					nwrite = write(tun_fd, buffer, (nread + sizeof(answers)));					


				}

				//清空
				memset(queryname, 0, sizeof(queryname));	
			}
		}
	

	}

	return 0;
}

