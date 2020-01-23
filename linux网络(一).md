> 搞不懂网络的话很多东西都不懂，本篇尤其是关于路由那一块，简直要了命，更是直接没搞明白，还得沉淀一段时间以后再补。


1. tun/tap
2. veth-pair
3. linux bridge
4. macvlan&ipvlan


上面都是非基础的东西，但是是需要解决并落地的东西，所以在学习完基础后就会开始搞，也是关于实际网络设备到云计算网络的转变。


# 协议栈
先说下`OSI七层模型`，这个模型是由`ISO`组织制定的用于划分网络层次的规则，定义了每一层的功能与数据结构。


![ce88d095-f382-4822-8969-2cae7b775d09.png](linux网络(一)_files/ce88d095-f382-4822-8969-2cae7b775d09.png)


我们知道的什么`tcp`，`udp`各种协议都被包含在这七层之中，但是协议都是协议，都是约定好的纸面的东西，大家都按照这个数据标准来处理。
比如数据的封装与解包：


![78ec13c0-316b-45ef-b4d4-18409c54024e.png](linux网络(一)_files/78ec13c0-316b-45ef-b4d4-18409c54024e.png)


![17aab707-6031-4a54-99b7-095012991e59.png](linux网络(一)_files/17aab707-6031-4a54-99b7-095012991e59.png)


标准与规范都定义好了，那总得有代码有函数去真正实现，让数据的上下传递符合协议标准，协议不同，那实际实现的代码就不同，因此很多很多不同协议的代码堆叠在一起，这些代码为上层提供调用接口，封装成数据，由此构成了一套成熟的代码集合，也就是协议栈。


![a8e8deaa-6b08-4b23-9cf2-82938851347d.png](linux网络(一)_files/a8e8deaa-6b08-4b23-9cf2-82938851347d.png)


> 协议栈就是协议套件的软件实现，是各层协议的总和


一个`协议栈`被实现好后，那`用户态`的app发出的数据自然都会传输到`协议栈`中，然后由内部的规则最后通过物理层的设备传输出去。但是呢，很多时候网络数据或者说`流量`的传输并非都是这么直来直去，或者说一开始的网络是这样的，在一个系统内，网络数据就是这么单纯的从上层到下层，出了这个系统后，就全靠网络设备去转发，比如`路由器`，比如`交换机`，其实现在也是这样的，然而随着`云计算`，`虚拟化`这些技术的兴起，越来越多的网络问题需要在一个系统内就解决，那`虚拟网络设备`自然也就应运而生，然而在说`虚拟网络设备`前还有个绕不开的点就是`路由规则`，因为`协议栈`需要根据`路由规则`才能决定将数据交给哪个`网络设备`。


# `路由决策原则`
顾名思义，这是`路由器`根据`路由表`中的信息，选择最佳的路径将数据转发出去，在不考虑转发方案的基础上，最重要的一点就是`路由表`信息，其中存储着三种路由信息：
1. 直连路由
2. 静态路由
3. 动态路由


通过`route`命令可以查看本机的`路由表信息`：
```
$route
Kernel IP routing table
Destination         Gateway          Genmask         Flags          Metric         Ref           Use         Iface
default            _gateway          0.0.0.0          UG             600            0             0          wlp3s0
10.1.44.0           0.0.0.0        255.255.255.0      U               0             0             0          docker0
172.16.141.0        0.0.0.0        255.255.255.0      U               0             0             0          vmnet8
192.168.40.0        0.0.0.0        255.255.248.0      U              600            0             0          wlp3s0
192.168.82.0        0.0.0.0        255.255.255.0      U               0             0             0          vmnet1
```
> 注意一下那个`docker0`的路由，其实在没有启动`docker`服务的时候，这条路由信息是不存在的，而启动后则插入了这条路由。


# 报文传输
> 一切都要从报文传输说起。


应用层(`TCP/IP模型`)的网络传输基本上都是通过`socket`系统调用将数据推入`协议栈`中，这也是`linux网络编程`的入口，先前学习过`socket`网络传输的流程，但是数据是怎么从`client`到达`server`的呢？就用一个简单的程序来测试一下：
```
/*==============================================================================
# Author: lang lyi4ng@gmail.com
# Filetype: C source code
# Environment: Linux & Archlinux
# Tool: Vim & Gcc
# Date: 2019.10.14
# Descprition: Randomly written code
================================================================================*/
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#define MAXLEN 1024


int main(void)
{
 /*socket file description*/
 int sockfd,connc;
 char *message = "This is test\n",buf[MAXLEN];
 struct sockaddr_in servaddr;


 sockfd = socket(AF_INET, SOCK_STREAM,0);
 if(sockfd == -1){
  perror("sock created");
  exit(-1);
 }


 /*set serverAddr default=0*/
 bzero(&servaddr, sizeof(servaddr));


 /*set serverAddr info*/
 servaddr.sin_family = AF_INET;
 servaddr.sin_port = htons(9999);
 servaddr.sin_addr.s_addr = inet_addr("127.0.0.1");


 connc = connect(sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr));


 if(connc == -1){
  perror("connect error");
  exit(-1);
 }
 write(sockfd, message, strlen(message));
 read(sockfd, buf, MAXLEN);
 close(sockfd);
 return 0;
}
```
研究过`socket`的连接模型，自然就应当知道，`TCP client`发起`connect`的时候就会与服务端开始产生通信，那切入点就从`connect`开始探究。
> linux网络流程可以将上面的程序自下而上分为四层：`驱动层`，`协议无关层`，`IP层`，`socket层`


## `connect`
直接内核源码看过去，`connect`的实现是在`net/socket.c`中定义的：
```
SYSCALL_DEFINE3(connect, int, fd, struct sockaddr __user *, uservaddr,
  int, addrlen)
```
从上往下来说：
1. `sockfd_lookup_light`是寻找`socket`实例
2. `move_addr_to_kernel`从用户空间拷贝套接字地址到内核空间
3. `security_socket_connect`安全检测，对协议本身的实现没有什么干扰
4. `sock->ops->connect`调用不同协议本身的`connect`


关于第四点需要看一个数组：
> 此处前置`socket_create` 中的`全局协议链表`，会去设置相应的`sock->ops`，参考[前置知识](https://blog.csdn.net/hxchuan000/article/details/51720270)


```
static struct inet_protosw inetsw_array[] =
{
 {
  .type = SOCK_STREAM,
  .protocol = IPPROTO_TCP,
  .prot = &tcp_prot,
  .ops = &inet_stream_ops,
  .flags = INET_PROTOSW_PERMANENT |
         INET_PROTOSW_ICSK,
 },


 {
  .type = SOCK_DGRAM,
  .protocol = IPPROTO_UDP,
  .prot = &udp_prot,
  .ops = &inet_dgram_ops,
  .flags = INET_PROTOSW_PERMANENT,
       },


       {
  .type = SOCK_DGRAM,
  .protocol = IPPROTO_ICMP,
  .prot = &ping_prot,
  .ops = &inet_sockraw_ops,
  .flags = INET_PROTOSW_REUSE,
       },


       {
        .type = SOCK_RAW,
        .protocol = IPPROTO_IP, /* wild card */
        .prot = &raw_prot,
        .ops = &inet_sockraw_ops,
        .flags = INET_PROTOSW_REUSE,
       }
};
```
对于`SOCK_STREAM`类型的调用的最终会是`inet_stream_connect`，这个才是真正去处理`connect`的函数。
> 这部分东西需要前置`sockfs`


## `inet_stream_connect`
这里需要注意的也只有一行而已：
```
err = __inet_stream_connect(sock, uaddr, addr_len, flags, 0);
```


## `__inet_stream_connect`
检查了地址长度和协议族，针对`AF_UNSPEC`协议族做了特殊的处理(去断开连接，然后根据返回来设置socket状态)，接着检查一下当前socket状态然后分别作不同的处理，总结一下就是只有状态为`SS_CONNECTING`或者是`SS_UNCONNECTED`才有操作，其余的就直接`goto out`了。
对于一个`socket`连接的话，理想上都应该是进入到`SS_UNCONECTED`的流程，因此就直接进入此流程去看。
```
err = sk->sk_prot->connect(sk, uaddr, addr_len);
```
这儿和先前的一样，都是已经确定的东西，因为使用的`传输层`协议是`TCP`，所以实际调用的`connect`方式是`tcp_v4_connect`。
> 后面就是收尾的处理了，有兴趣的话去看参考资料，这儿不去研究。


## `tcp_v4_connect`
先不急着去看实现流程，单纯的想一想，这个函数也就是去实现一个`TCP`协议的三次握手，实际上来说就是发送一个`SYN`报文，然后处理一个`ACK`报文。那么代码中就应该存在的逻辑有：
1. 报文格式的构造或者说处理
2. 网络
 
那对于我来说，我需要关注报文本身吗？很明显不需要，我所关注的只是单纯的`网络`，即代码是怎么知道把这个报文发向哪儿的？再扩展一点，看一下`tcp_v4_connect`的传入参数可以看出来，人为去控制的关于地址的信息就只有`uaddr`，追其来源就是如下信息：
```
 servaddr.sin_family = AF_INET;
 servaddr.sin_port = htons(9999);
 servaddr.sin_addr.s_addr = inet_addr("127.0.0.1");
```
换成`uaddr`的结构体信息也就是：
```
struct sockaddr_in {
  __kernel_sa_family_t sin_family; /* Address family */
  __be16 sin_port; /* Port number */
  struct in_addr sin_addr; /* Internet address */


  /* Pad to size of `struct sockaddr'. */
  unsigned char __pad[__SOCK_SIZE__ - sizeof(short int) -
   sizeof(unsigned short int) - sizeof(struct in_addr)];
};
```
> 其实去分析的话也会发现关于报文的处理其实并不是很多，大部分还都是关于路由的处理。
1.如果用户已经设置源IP，则直接使用设置的源IP
2.如果没有设置源IP则根据目的ip和路由查找源IP
3.如果用户已经设置源port，则直接使用源Port
4.如果没有设置源PORT 根据目的IP port 和当前系统的establish tcp hash表查找sport。
5.查找目的路由
6.将TCP sock 状态设置为TCP_SYN_SENT。
7.根据已经查找到的路由及路由出口设备的能力设置一些GSO TSO标志等。sk_setup_caps。


整个函数上来就是强制类型转换：
```
 struct sockaddr_in *usin = (struct sockaddr_in *)uaddr;
 struct inet_sock *inet = inet_sk(sk);
 struct tcp_sock *tp = tcp_sk(sk);
```
> 我们知道unix中万物皆文件，没错，bsd在实现上把socket设计成一种文件，然后通过虚拟文件系统的操作接口就可以访问socket，而访问socket时会调用相应的驱动程序，从而也就是使用底层协议进行通信，需要去了解一下不同的`socket`结构体意义：
1. `struct socket`：这是基本的`BSD socket`，应用程序通过系统调用创建的`socket`都是这个结构体，是基于`VFS`创建出来的，类型主要有三种：`流式SOCK_STREAM`，`数据报SOCK_DGRAM`，`原始套接字SOCK_RAW`
2. `struct sock`：这是网络层`socket`，对应有`TCP`，`UDP`，`RAW`三种
3. `struct inet_sock`：`INET域`的`socket`，是对`struct sock`的扩展，提供了`INET域`的属性，比如`TTL`，`组播列表`，`IP地址`，`端口`等
4. `struct raw_sock`：`RAW`协议的`socket`，针对`struct inet_sock`的扩展，处理`ICMP`相关的内容
5. `struct udp_sock`：`UDP`协议的`socket`，针对`struct inet_sock`的扩展
6. `struct tcp_sock`：`TCP`协议针对`inet_connextion_sock`的扩展，增加了`滑动窗口`，`拥塞控制`等专用属性
7. `struct inet_connection_sock`：是所有面向连接的`socket`表示，基于`struct inet_sock`的扩展
8. `struct inet_timewait_sock`：网络层用于超时控制的`socket`
9. `struct tcp_timewait_sock`：`TCP`协议用于超时控制的`socket`


然后简单地判断下地址长度(`if (addr_len < sizeof(struct sockaddr_in))`)和协议族后(`if (usin->sin_family != AF_INET)`)就进入到了网络地址设置。


首先是设置下一跳地址和目的地址，都设置成用户定义的地址：
```
nexthop = daddr = usin->sin_addr.s_addr;
```
获取`ip路由选项`
```
inet_opt = rcu_dereference_protected(inet->inet_opt,
                         lockdep_sock_is_held(sk));
```
如果有路由选项的话则把下一跳设置成`ip路由选项`中的第一跳地址，同时设置到`源端口`和`目的端口`。
```
nexthop = inet_opt->opt.faddr;
orig_sport = inet->inet_sport;
orig_dport = usin->sin_port;
```
设置`flowi4`流控，也就是路由表查找的键值`fl4 = &inet->cork.fl.u.ip4;`，接着就是调用`ip_route_connect`进行路由查找。
路由查找先往后放，因为越过了`socket create`的流程，所以会发现现在很多东西都很别扭，比如`flowi4`，`inet_opt`这些都是怎么来的？


![4899ae06-a0e3-48cd-96d4-d14a83054695.png](linux网络(一)_files/4899ae06-a0e3-48cd-96d4-d14a83054695.png)


整了个函数流的图出来，可以看出来最终使用到的信息`inet_sock`来源于最初的一个`struct socket *sock`，中途只有一个`inet_sk`的强制类型转换的操作。那实际上来说，关于后续用到的所有数据，就已经封装到`struct socket *sock`中了。


## `__sock_create`
> 这儿不去深究整个逻辑，就看`struct socket *sock`是怎么被创建出来的


`SYSCALL_DEFINE3(socket, int, family, int, type, int, protocol)` -> `sock_create` -> `__sock_create`这个函数流完成了一个`socket`的创建，而基本核心逻辑都在`__sock_create`之中。


首先一个前后顺序问题就是先创建了`socket对象`，然后才影射出`socket文件描述符`。
```
 /*
  * Allocate the socket and allow the family to set things up. if
  * the protocol is 0, the family is instructed to select an appropriate
  * default.
  */
 sock = sock_alloc();
```
首先就是在`VFS`上分配一个`struct socket`对象，之后就是针对此对象的处理
```
pf->create(net, sock, protocol, kern);
```
然而`pf->create`得往前看是`pf = rcu_dereference(net_families[family]);`，而`family`根据代码的话是传入的`AF_INET`，那关于这个数组继续往前看
```
static const struct net_proto_family __rcu *net_families[NPROTO] __read_mostly;


struct net_proto_family {
 int family;
 int (*create)(struct net *net, struct socket *sock,
      int protocol, int kern);
 struct module *owner;
};
```
> 越过一些知识


这个数组是在`inet_init`中被初始化的：`(void)sock_register(&inet_family_ops);`
```
static const struct net_proto_family inet_family_ops = {
 .family = PF_INET,
 .create = inet_create,
 .owner = THIS_MODULE,
};
```
那么`pf->create`就是`inet_create` :)


好，先前提到过关于`sock->ops`的前置知识，现在就直接看一下，同样是在`inet_init`的过程中：
```
static struct list_head inetsw[SOCK_MAX];
 /* Register the socket-side information for inet_create. */
 for (r = &inetsw[0]; r < &inetsw[SOCK_MAX]; ++r)
  INIT_LIST_HEAD(r);


 for (q = inetsw_array; q < &inetsw_array[INETSW_ARRAY_LEN]; ++q)
  inet_register_protosw(q);
```
`inetsw`数组的每一个元素都是一个双向链表，在初始化每个元素的头后，将`inetsw_array`数组的元素使用`inet_register_protosw`函数注册到`inetsw`数组中，而关于`inetsw_array`数组上面有说到。


回来继续看代码，在`inet_create`中第一个重要的操作就是关于`struct sock`对象的创建，先前说过`struct socket`和`struct sock`的区别，这个对象中有关于网络层的信息，也是需要着重关注的信息。
```
sk = sk_alloc(net, PF_INET, GFP_KERNEL, answer_prot, kern);
```
接着就是针对`sk`的数据初始化
```
sock_init_data(sock, sk);
```
主要设置一些队列信息还有连接状态等，也就是与`IP`协议相关联的部分。再往下走就到了需要去着重关注的一步：
```
 if (sk->sk_prot->init) {
  err = sk->sk_prot->init(sk);
```
这儿的设置还是回顾到`sk_alloc()`函数中`sk->sk_prot = sk->sk_prot_creator = prot;`，即`inetsw_array`中的元素`tcp_prot`，那这儿真正使用的函数是：
```
.init = tcp_v4_init_sock
```
到这就闭环一下`__sock_create`和`inet_create`，因为这两个里面的其余操作已经无关紧要了，因为他们最终的功效都是去调整生成最终要被利用的`struct sock`对象。


## `tcp_v4_init_sock`
操作比较少，实际就两个，先说下第二个就是设置了传输层的各种处理函数接口，暂时并没有用起来。而第一个也只是初始化各种`tcp`参数信息。
```
tcp_init_sock(sk);
icsk->icsk_af_ops = &ipv4_specific;
```
什么前置信息都没有，这时候才想到，这些信息不会是等到要用时才开始初始化的吧？


# 重回`connect`
> 创建的socket对象并不是很复杂，也没有什么有用的信息，因此还是回来重新分析先前的流程


上面说道`ip_route_connect`还有`fl4`的问题，一路分析过来其实是没有看到`fl4`是怎么被填充的，因此就直接跟入`ip_route_connect`去看逻辑。
首先有个初始化的操作，如果跟踪一下函数链就是如下：
```
ip_route_connect_init -> flowi4_init_output
```
这个函数会去初始化`fl4`的数据，例如`fl4->daddr`，`fl4->saddr`，`fl4->fl4_dport`，`fl4->fl4_sport`，但是并非都是已经设置好值的，因为想要发送第一个`SYN`报文，就需要完整的`来源/目的地址`，`来源/目的端口`，然而在客户端的`socket connect`中，只有`目的地址/端口`可以被用户提供出来，`来源端口`可以从未用端口中动态分配一个，然而一个主机上可能有多个IP，那么`来源地址`如果错误的话，就很有可能造成数据不可达，因此这时候需要有路由参与在内。


而关于这个`来源地址`在接口层次上还分为`bind`和`no-bind`类型，如果是`bind`类型的话来源地址就是`bind`地址，但是`no-bind`类型的话则需要根据路由的结果确定`来源地址`。


这儿再说关于路由的问题，一个数据包传输到本地后，需要先在`IP层`查找路由，然后在`传输层`查找socket，因此为了高效利用，linux内核提供了一个特性`ip_early_demux`，其能力就是在`socket`中增加一个`dst`字段作为缓存路由，`skb`在查找路由前优先查找`socket`，找到的话就把缓存的`dst`设置到`skb`，那么再去查找路由的时候发现已经有`dst`了，就省去查找路由的过程。
复制粘贴点题外话：
```
所有的路由器设计都要遵循以下规则：
IF 目的地址配置在本机
    THEN 本机接收
ELSE
    查找路由表并在找到路由的情况下转发
END
```


回来继续看`ip_route_connect`，初始化完`fl4`后会有一个判断，因为`src`是没有设置的，所以会自动进入到`__ip_route_output_key`的流程，接着在`ip_route_output_key_hash`中填充一些`fl4`的数据然后进入到`ip_route_output_key_hash_rcu`中。
> 内核从`3.6`开始，就没有了`ip_route_output_slow`这个函数了，因为`kernel 3.6`以后去除了针对路由cache的支持，数据想要发送出去就必须查找路由表，但是如果完全依靠即时的`alloc`明显会造成巨大的内存开销，因此在此之后开始缓存查找结果的`nexthop`。


函数开始便是三个路由条件判断：
```
if (fl4->saddr) {  //来源地址，为空
if (fl4->flowi4_oif) {   //出口设备，为0
if (!fl4->daddr) {  //目标地址，为用户定义地址
```
三个条件都没有符合，直接进入到`err = fib_lookup(net, fl4, res, 0);`函数，这个是路由转发表检索函数，`fl4`是查找条件，而`res`是路由查找结果。


因为此时的`来源地址`为空，那么策略路由的from关键字将无法匹配到所有没有bind地址的程序发出的数据包，实际上来说这就导致不会进入到任何一张自定义策略路由表中。
> 简单点说，策略路由就是根据`来源地址`，`目的地址`，`入接口`，`出接口`等元素决定数据包在路由前是否进入到该张`策略路由表`。


实际分析代码，在`fib_lookup`中会优先判断是否有(自定义？)`路由策略(fib_has_custom_rules)`，从而判断如何进行路由查询。
这儿涉及到一部分策略路由初始化(`fib_rules_init`)相关的东西，分为非协议相关初始化和协议相关初始化，非协议相关主要为操作，协议相关主要为网络。
例如`AF_INET协议族`初始化过程中关于三张默认策略路由规则的初始化：
```
static int fib_default_rules_init(struct fib_rules_ops *ops)
{
 int err;


 err = fib_default_rule_add(ops, 0, RT_TABLE_LOCAL, 0);
 if (err < 0)
  return err;
 err = fib_default_rule_add(ops, 0x7FFE, RT_TABLE_MAIN, 0);
 if (err < 0)
  return err;
 err = fib_default_rule_add(ops, 0x7FFF, RT_TABLE_DEFAULT, 0);
 if (err < 0)
  return err;
 return 0;
}
```
> 套用别人的总结
```
策略路由的初始化做的事情其实很清晰：
对于非协议相关的初始化：
    1. 向RT_NETLINK注册三个子命令，分别用于策略路由的增加、删除和查询；
    2. 初始化管理各个协议族fib_rules_ops对象的链表和锁；
    3. 向网络设备接口层注册回调，当网卡状态发生变化时，能够更新策略路由数据库；
对于协议族相关的初始化，以AF_INET为例：
    1. 向框架注册自己的fib_rules_ops对象；
    2. 创建三条默认的策略路由， 分别用于查询local、main和default表；
```


这儿要注意三条默认的`rule`的`action`都是`FR_ACT_TO_TBL`,
`AF_INET协议族`初始化后会设置`net->ipv4.fib_has_custom_rules = false;`，但是我们手动`fib_nl_newrule`一下(`sudo ip rule add fwmark 3 table local`)，让代码逻辑进入到`__fib_lookup`，其中函数内部涉及到一个`l3mdev`设备的逻辑，是`4.8内核`开始引入的新机制，如果没有设置`VRF`的话可以暂时不用看。那么实际的路由逻辑在`fib_rules_lookup`之中。
> `fib_nl_newrule`会调用`fib4_rule_configure`，然后设置`net->ipv4.fib_has_custom_rules = true;`，其实我这儿还没有搞清楚默认的到底是`false`还是`true`，但是手动置为`true`吧


```
err = fib_rules_lookup(net->ipv4.rules_ops, flowi4_to_flowi(flp), 0, &arg);
```
`net->ipv4.rules_ops`中的`rules_list`链表保存了当前`net namespace`所有的路由策略。通过`list_for_each_entry_rcu`遍历链表，然后通过`fib_rule_match`匹配策略。
这个可以先看一下当前情况：
```
$ip rule
0: from all lookup local
32765: from all fwmark 0x3 lookup local
32766: from all lookup main
32767: from all lookup default
```
而关于函数`match`的方法
```
通用规则匹配
1）如指定入接口，数据包的入接口必须和策略rule中指定的入接口相同； //iif eth1
2）如指定出接口，二者的出接口必须相同；  //oif eth0
3）如指定流标记，二者的流标记必须相同； //fwmark 0x3
4）如指定隧道ID，二者的隧道ID必须相同； //tunid


另外，针对IPv4协议：
5）策略rule中指定的源IP地址与数据包的源IP地址，与掩码进行位与操作，结果必须相同；//from
5）策略rule中指定的目的IP地址与数据包的目的IP地址，与掩码进行位与操作，结果必须相同； //to
7）如指定TOS值，二者的TOS值必须相同； //服务类型，即指定服务的流量 //tos
```
首先遍历到的`0: from all lookup local`在进入到`fib4_rule_match`后会因为什么都没有设置而直接返回`1`,也就是直接匹配到。此刻本条规则的大致数据如下：
```
r->action = FR_ACT_TO_TBL;
r->pref = 0;
r->table = RT_TABLE_LOCAL;
r->flags = 0;
```


匹配到规则后返回至`fib_rules_lookup`,判断下`action`接后执行`ops->action`的操作，此刻应该是`fib4_rule_action`，在没有使用`l3mdev`的情况下，使用`rule->table`作为`table id`，然后调用`fib_get_table`获取该表，最后通过`fib_table_lookup`进行路由项查找。
> kernel支持两种FIB的存储方式：一种hash，一种单词查找树trie，通过内核编译选项`CONFIG_IP_FIB_HASH`和`CONFIG_IP_FIB_TRIE`决定，不过新版kernel取消了针对hash的支持


看一下我自己的`LOCAL表`信息：
```
broadcast 127.0.0.0 dev lo proto kernel scope link src 127.0.0.1 
local 127.0.0.0/8 dev lo proto kernel scope host src 127.0.0.1 
local 127.0.0.1 dev lo proto kernel scope host src 127.0.0.1 
broadcast 127.255.255.255 dev lo proto kernel scope link src 127.0.0.1 
broadcast 192.168.40.0 dev wlp3s0 proto kernel scope link src 192.168.43.42 
local 192.168.43.42 dev wlp3s0 proto kernel scope host src 192.168.43.42 
broadcast 192.168.47.255 dev wlp3s0 proto kernel scope link src 192.168.43.42 
```
而关于查找算法，需要知道关于[Internet路由之路由表查找算法概述-哈希/LC-Trie树/256-way-mtrie树](https://blog.csdn.net/dog250/article/details/6596046)的前置知识，这个我不会，甚至`fib_table_lookup`这个函数我都看不太明白，因此只能换个方法去反推，最后的结果是返回的`err`，搜了一下整个函数中只有一个关于`err`的赋值：
```
err = fib_props[fa->fa_type].error;
```
关于这个数组内容如下：
```
const struct fib_prop fib_props[RTN_MAX + 1] = {
 [RTN_UNSPEC] = {
  .error = 0,
  .scope = RT_SCOPE_NOWHERE,
 },
 [RTN_UNICAST] = {
  .error = 0,
  .scope = RT_SCOPE_UNIVERSE,
 },
 [RTN_LOCAL] = {
  .error = 0,
  .scope = RT_SCOPE_HOST,
 },
 [RTN_BROADCAST] = {
  .error = 0,
  .scope = RT_SCOPE_LINK,
 },
 [RTN_ANYCAST] = {
  .error = 0,
  .scope = RT_SCOPE_LINK,
 },
 [RTN_MULTICAST] = {
  .error = 0,
  .scope = RT_SCOPE_UNIVERSE,
 },
 [RTN_BLACKHOLE] = {
  .error = -EINVAL,
  .scope = RT_SCOPE_UNIVERSE,
 },
 [RTN_UNREACHABLE] = {
  .error = -EHOSTUNREACH,
  .scope = RT_SCOPE_UNIVERSE,
 },
 [RTN_PROHIBIT] = {
  .error = -EACCES,
  .scope = RT_SCOPE_UNIVERSE,
 },
 [RTN_THROW] = {
  .error = -EAGAIN,
  .scope = RT_SCOPE_UNIVERSE,
 },
 [RTN_NAT] = {
  .error = -EINVAL,
  .scope = RT_SCOPE_NOWHERE,
 },
 [RTN_XRESOLVE] = {
  .error = -EINVAL,
  .scope = RT_SCOPE_NOWHERE,
 },
};
```
这个赋值在一个链表的循环里面，而前置条件是：
```
  if ((BITS_PER_LONG > KEYLENGTH) || (fa->fa_slen < KEYLENGTH)) {
   if (index >= (1ul << fa->fa_slen))
    continue;
  }
  if (fa->fa_tos && fa->fa_tos != flp->flowi4_tos)
   continue;
  if (fi->fib_dead)
   continue;
  if (fa->fa_info->fib_scope < flp->flowi4_scope)
   continue;
```
上述循环找到一条具体的路由，至于判断条件基本都是看最后一个，也就是关于`scope`的长度。
`flp->flowi4_scope`初始化是`RT_SCOPE_UNIVERSE=0`，然后在`ip_route_output_key_hash`中设置`fl4->flowi4_scope = ((tos & RTO_ONLINK) ?RT_SCOPE_LINK : RT_SCOPE_UNIVERSE);`也还是`RT_SCOPE_UNIVERSE`(因为IP_TOS default=0)，这个条件就是任何路由都会满足。
> 如果设置了`MSG_DONTROUTE`，则`TOS = RTO_ONLINK`，从而导致`scope = RT_SCOPE_LINK`


往下走是叶子节点的链表遍历。
`fa`是`fib_alias`对应的是一条路由，多个`fib_alias`可以共享一个相同的`fib_info`，这是真实路由信息，比如设备，下一跳什么的，而其中的`fib_info->fib_nh[nhsel]`代表了下一跳地址。这儿的`nhsel`一般是`1`，除非是多路径支持，不然一条路由一般只有一个下一跳。
那么从上往下到`return err`需要过的条件有：
```
   if (fi->fib_flags & RTNH_F_DEAD) // fi->fib_flags != RTNH_F_DEAD(失效的地址)，所以先刷新路由。
    continue;
   if (nh->nh_flags & RTNH_F_DEAD)  // nh->nh_flags != RTNH_F_DEAD
    continue;
   if (in_dev &&   // fib_flags == arg->flags == 0
       IN_DEV_IGNORE_ROUTES_WITH_LINKDOWN(in_dev) &&
       nh->nh_flags & RTNH_F_LINKDOWN &&
       !(fib_flags & FIB_LOOKUP_IGNORE_LINKSTATE))
    continue;
   if (!(flp->flowi4_flags & FLOWI_FLAG_SKIP_NH_OIF)) {   //flp->flowi4_oif == 0
    if (flp->flowi4_oif &&
        flp->flowi4_oif != nh->nh_oif)
     continue;
   }
```
> 有好多路由本身的信息又要涉及到路由添加中的逻辑，那个后面再说吧。


而如上的逻辑其实都是写在`found`中的，那么得重新往前看，用到的比较重要的一个数据就是`const t_key key = ntohl(flp->daddr);`，实际上说来说去，还是地址比较在里面。
去除关于`trie路由查找算法`的相关知识，就会在此函数中根据目的地址找到一个路由项，然后填充结果：
```
local 127.0.0.0/8 dev lo proto kernel scope host src 127.0.0.1 
```
最后一直返回的`err = 0`,又因为`res->type = RTN_LOCAL`，且`fl4->saddr = 0`，所以`fl4->saddr = 127.0.0.1`且`fl4->flowi4_oif = loopback_dev`，接着创建路由缓存条目`__mkroute_output`。
直接看到`rt_set_nexthop(rth, fl4->daddr, res, fnhe, fi, type, 0, do_cache);`，然后重新填充`fl4`的数据
```
/* Reset some input parameters after previous lookup */
static inline void flowi4_update_output(struct flowi4 *fl4, int oif, __u8 tos,
     __be32 daddr, __be32 saddr)
{
 fl4->flowi4_oif = oif;
 fl4->flowi4_tos = tos;
 fl4->daddr = daddr;
 fl4->saddr = saddr;
}
```
后面的流程又是个重复，就不跟了，直接退出来。
```
 if (!inet_opt || !inet_opt->opt.srr)
  daddr = fl4->daddr;


 if (!inet->inet_saddr)
  inet->inet_saddr = fl4->saddr;
 sk_rcv_saddr_set(sk, inet->inet_saddr);
 inet->inet_dport = usin->sin_port;
 sk_daddr_set(sk, daddr);
```
经过设置后，`saddr = 127.0.0.1; daddr = 127.0.0.1; dport = 9999`
```
rt = ip_route_newports(fl4, rt, orig_sport, orig_dport,
          inet->inet_sport, inet->inet_dport, sk);
```
动态设置端口。
```
sk_setup_caps(sk, &rt->dst);
```
设置TCP出口路由缓存，也就是先前一直说的`dst`，都整完了后就是发送第一个`SYN包`了。


# 参考资料
* [OSI协议栈基础](https://blog.csdn.net/weixin_44132032/article/details/90720064)
* [协议栈是什么](https://www.cnblogs.com/liushui-sky/p/6490115.html)
* [linux内核网络协议栈架构分析，全流程分析-干货](https://blog.csdn.net/zxorange321/article/details/75676063)
* [Linux 网络栈剖析](https://www.ibm.com/developerworks/cn/linux/l-linux-networking-stack/)
* [路由决策原则](https://www.xuebuyuan.com/1150166.html)
* [理解 Linux 网络栈（1）：Linux 网络协议栈简单总结](https://www.cnblogs.com/sammyliu/archive/2016/02/29/5225623.html)
* [Socket connect 等简要分析](https://www.cnblogs.com/codestack/p/11098262.html)
* [Linux内核网卡驱动程序](http://mark-shih.blogspot.com/2011/01/)
* [套接字之connect系统调用](http://www.linuxtcpipstack.com/154.html)
* [Socket层实现系列 — connect()的实现](https://blog.csdn.net/zhangskd/article/details/45508569)
* [网络层路由系统（linux网络协议栈笔记）](https://blog.csdn.net/viewsky11/article/details/53711651)
* [linux网络协议栈--路由流程分析](https://www.cnblogs.com/newjiang/p/7493686.html)
* [Linux TCP/IP 协议栈之 Socket的实现分析(Connect客户端发起连接请求)](http://blog.chinaunix.net/uid-13746440-id-3076372.html)
* [TCP主动打开 之 第一次握手-发送SYN](http://www.linuxtcpipstack.com/447.html)
* [Linux内核网络协议栈4－创建socket（续）](https://www.iteye.com/blog/hellojavaer-1096562)
* [Linux内核分析 - 网络[十四]：IP选项](https://blog.csdn.net/qy532846454/article/details/7498536)
* [浅析linux kernel network之socket创建](http://blog.sae.sina.com.cn/archives/3787)
* [socket和sock的一些分析](http://abcdxyzk.github.io/blog/2015/06/12/kernel-net-sock-socket/)
* [TCP相关的sock数据结构及使用](https://blog.csdn.net/sinat_20184565/article/details/79720713)
* [Linux内核-协议栈-主要函数调用栈](https://yq.aliyun.com/articles/632401/)
* [Linux connect系统调用](https://blog.csdn.net/u010039418/article/details/79971453)
* [Linux内核协议栈的socket查找缓存路由机制](https://blog.csdn.net/dog250/article/details/42609663)
* [Linux路由应用-使用策略路由实现访问控制](https://blog.csdn.net/dog250/article/details/6685633)
* [Linux VRF(Virtual Routing Forwarding)的原理和实现](https://blog.csdn.net/dog250/article/details/78069964?utm_source=tuicool&utm_medium=referral)
* [linux内核 策略路由之查找](https://blog.csdn.net/guodong1010/article/details/52246239)
* [tcp/ip 协议栈Linux内核源码分析七 路由子系统分析二 策略路由](https://blog.csdn.net/fuyuande/article/details/90611479)
* [策略路由之初始化](http://www.ishenping.com/ArtInfo/2674949.html)
* [LINUX RP_FILTER配置引起的组播断流问题](https://www.cnblogs.com/smith9527/p/11054232.html)
* [Linux3.5内核以后的路由下一跳缓存](https://blog.csdn.net/dog250/article/details/50809816)
* [Linux 路由表](https://jin-yang.github.io/post/network-route-table_init.html)
* [Internet路由之路由表查找算法概述-哈希/LC-Trie树/256-way-mtrie树](https://blog.csdn.net/dog250/article/details/6596046)
* [IPv4 route lookup on Linux](https://vincent.bernat.ch/en/blog/2017-ipv4-route-lookup-linux)
* [#Linux协议栈你学得会# 之 本机地址 vs 127.0.0.1](https://my.oschina.net/u/2310891/blog/621672)
* [fib系统分析（linux网络协议栈笔记）](https://blog.csdn.net/viewsky11/article/details/53437092)
* [Linux路由表](https://www.jianshu.com/p/8499b53eb0a5)
* [设置socket选项getsockopt和setsockopt接口](http://www.yangxg.com/blog/id/1449037641)
* [TCP/IP学习(40)——Kernel中路由表的实现(3)](http://biancheng.dnbcw.net/linux/342816.html)