> 其实关于收包的流程都没有去研究，但是实际上在之前的很多文章中都或多或少了解了情况。因此留个坑以后有机会再补，现在主要还是去学习一下虚拟设备。


# `tun/tap`
> 这其实是两个东西，`tun`属于三层设备，而`tap`则属于二层设备



这是`2.4.x`版本以后实现的虚拟网络设备，完全由软件实现，功能上和硬件网卡没有差别，同样也需要配套的驱动程序才能运行起来。而因为是虚拟网卡实际上是没有真实的`dev`的，因此实际上来说该驱动同时需要实现两个功能：
1. `字符设备驱动`
2. `网卡驱动`


其中`字符设备驱动`的逻辑模拟物理链路的数据接收和发送，将网络分包在内核与用户态间传送，而`网卡驱动`部分则是和`协议栈`交互数据。
那么信息的发送可能是这样的：
1. 应用程序发起网络请求
2. 进入协议栈后经过路由查询应该走虚拟网卡
3. 数据进入虚拟网卡，处理后发送给应用层程序
4. 数据从程序再次进入协议栈，重新路由到真实网卡
5. 通过真实网卡把数据发送出去


实际上来说`tun`充当了一个隧道，因此`openvpn`也是通过此方法实现的。可以写一个简单的程序实现如下的功能：
* 打印出每一个经过虚拟网卡的流量的信息


如果是`tun`模式的话应用程序可以`read`到的数据是一个个数据包，也就是`Raw Data`。
```
/*==============================================================================
# Author: lang lyi4ng@gmail.com
# Filetype: C source code
# Environment: Linux & Archlinux
# Tool: Vim & Gcc
# Date: 2019.12.17
# Descprition: Create tun/tap veth
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
int main(int argc, char *argv[])
{
 char buffer[BUFSIZ], veth_name[IFNAMSIZ] = "tunveth1";
 int i, tun_fd, nread;
 struct ethhdr *eth;
 struct iphdr *iph;
 struct in_addr saddr, daddr; 
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

  if (iph->version ==4) {  
   printf("\nRead %d bytes from device %s\n", nread, veth_name);
   memcpy(&saddr.s_addr, &iph->saddr, 4);
   memcpy(&daddr.s_addr, &iph->daddr, 4);
   printf("Source host:%s\n", inet_ntoa(saddr));
   printf("Dest host:%s\n", inet_ntoa(daddr));
  }
 }
 return 0;
}
```
因为数据流量没有经过链路层，所以数据包中是没有`ethhdr`的，也就是没有`以太网帧`，那么数据就是直接从`iphdr`开始，因此通过强制类型转换就可以直接从数据中提取需要的值。
那接下来就尝试伪造响应，就以一个`DNS`查询的请求来做实验，就是给`tunveth.com`这个域名解析到一个`99.1.1.25`的IP上。
首先先抓取到所有的`DNS`请求并解析，后面再伪造数据包，其实这儿我原本的想法是直接在程序中硬编码返回包信息，后来我发现这就是一个傻逼行为，虽然在`wireshark`中包是构造出来了，但是好象是`checksum`被整错了，所以导致出了点问题，因此数据包肯定是在`协议栈`里被丢弃了，所以还不如再整一个`socket`把包发出去然后再接收返回包修改后写入网卡来的方便高效。
先挂出我的半成品：
```
/*==============================================================================
# Author: lang lyi4ng@gmail.com
# Filetype: C source code
# Environment: Linux & Archlinux
# Tool: Vim & Gcc
# Date: 2019.12.17
# Descprition: Create tun/tap veth
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
```
玩法可以更多样一点，因为请求和响应我们都能够控制，那例如`openvpn`的例子，就是将请求在程序中再次通过`openssl`加密后再直接通过`socket`发送出去，但是其中的坑点也要尤为注意一点：
1. `网络字节序`和`主机字节序`的转换，主要涉及到大小端问题，而`网络字节序`默认是大端序，`主机字节序`一般为小端序
2. `checksum`的校验上，有固定的算法，但是针对`udp/tcp`需要添加一个伪首部再参与计算


不过这些其实也不算什么大问题，因为各种成熟的`api`其实都解决了这些问题，除非像上面这份代码一样采用的硬编码伪造的方式才会出现这种情况。毕竟只是一块网卡，要涉及到真正的使用的话还是涉及到路由的相关知识，例如翻墙这样的操作 : )。


# 参考资料
* [虚拟化的层次与机制](https://blog.csdn.net/mayp1/article/details/51296682)
* [[原创] 详解云计算网络底层技术——虚拟网络设备 tap/tun 原理解析](https://www.cnblogs.com/bakari/p/10450711.html#2770904093)
* [虚拟网卡 TUN/TAP 驱动程序设计原理](https://www.ibm.com/developerworks/cn/linux/l-tuntap/index.html)
* [tun/tap运行机制](http://vinllen.com/tun-tap/)
* [Linux虚拟网络设备 TUN/TAP 与 VETH pair 的差异](http://sunyongfeng.com/201704/networks/tuntap_veth)
* [2.1.1.2.1 OpenVPN原理与实现浅析](https://github.com/suhao/awesome/wiki/2.1.1.2.1-OpenVPN%E5%8E%9F%E7%90%86%E4%B8%8E%E5%AE%9E%E7%8E%B0%E6%B5%85%E6%9E%90)
* [simpletun.c](http://www.cis.syr.edu/~wedu/seed/Labs/VPN/files/simpletun.c)
* [OpenVPN原理与实现浅析](https://github.com/suhao/awesome/wiki/2.1.1.2.1-OpenVPN%E5%8E%9F%E7%90%86%E4%B8%8E%E5%AE%9E%E7%8E%B0%E6%B5%85%E6%9E%90)
* [C++直接获取IP报文并打印IP地址实战](https://blog.csdn.net/chengqiuming/article/details/89598131)
* [IP协议号列表](https://zh.wikipedia.org/wiki/IP%E5%8D%8F%E8%AE%AE%E5%8F%B7%E5%88%97%E8%A1%A8)
* [DNS报文格式解析（非常详细）](http://c.biancheng.net/view/6457.html)
* [DNS协议 报文格式 ](http://09105106.blog.163.com/blog/static/2483578201342584441807/)
* [IP header checksum的处理 ](http://blog.sina.com.cn/s/blog_694f2ae701019var.html)
* [IP/TCP/UDP中Checksum的计算](http://www.voidcn.com/article/p-htnclmhf-wq.html)
* [UDP 协议解析 - 1](https://www.cnblogs.com/sxiszero/p/11565108.html)
* [udp_8c](http://minirighi.sourceforge.net/html/udp_8c-source.html)