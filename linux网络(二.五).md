> 本来应该算是`五`的，结果一想内容上应该算是承接的`二`的，那就算是个`二.五`吧，讲一讲`内核协议栈`的接收上的一些事。


`链路层`以及以前的就不细说了，太麻烦了，而其中最为称道的有如下几个理念：
1. `NAPI`和`非NAPI`模式
2. `RPS`和`RFS`
3. `input_pkt_queue`


但这些涉及到了驱动开发，所以就直接看到了最后的函数`__netif_receive_skb_core`，这个函数决定了怎样将一个`skb`包送到`ip layer`去。
```
type = skb->protocol;
```
从`skb`获取到下层的协议是什么，然后再通过`deliver_ptype_list_skb`设置设备的指定协议，最后再通过`ret = pt_prev->func(skb, skb->dev, pt_prev, orig_dev);`发送数据，而这个协议函数在正常使用的情况下都会是`ip_rcv`。
> 其实这部分还有非常多的判断和条件，并非如此简单


# `IP layer`
> 数据接收上其实比发送简单很多，大多是解包或者是`checksum`的计算


`ip_rcv`接收到`skb`后会根据`RFC1122`去校验下`iphdr`中的`ihl`和`version`，然后再计算一下`checksum`是否正确，这儿是有固定的算法的，大致逻辑就是:
1. 计算前把Checksum字段置0；
2. 将IP Header中每两个连续的字节当成一个16bit数，对所有的16bit数进行求和，在求和过程中，任何溢出16bit数范围的求和结果都需要进行回卷——将溢出的高16bit和求和结果的低16bit相加；
3. 对最终的求和结果按位取反，即可得到IP Header Checksum


然而关于验证的方法就简单很多：
```
只需进行Checksum计算中的第二步，若最终结果为0xFFFF则说明IP Header无差错。
```
> 关于`tcp/udp`也有`checksum`的计算，不过得有伪首部参与其中，伪首部的大概数据结构如下
```
struct vhdr {
 __be32 saddr;
 __be32 daddr;
 __u8 zeroadd;
 __u8 protocol;
 __u16 size;
};
```


等一系列检验操作结束后调用`NF_INET_PRE_ROUTING`上注册的函数，这是一个`netfilter`在协议栈中的钩子，主要是按照既定的规则去处理数据包，例如修改或者丢弃等等，最后还保留的数据包会由`ip_rcv_finish`来作处理。
> 实际上没有去配什么iptables的话，这儿可以理解成数据包是直接进入到`ip_rcv_finish`中的


```
    if (net->ipv4.sysctl_ip_early_demux &&
        !skb_dst(skb) &&
        !skb->sk &&
        !ip_is_fragment(iph)) {
```
函数优先判断了`skb`是否满足如下四个条件：
1. 系统启用的`early_demux`
2. `skb`的路由缓存为空
3. `skb`的`sock`为空
4. 非分片的包


关于第一点，其实先前在发包时候就简单提过，但是并不详细，这涉及到一点历史原因。假设一个tcp数据包到到达后，会优先查找`skb`对应的路由，决定发送到哪儿，然后再去查找`skb`对应的`socket`，然而其实在通常情况下，只要`socket`相同的话他们的路由就是相同的，那么将`skb`的路由缓存到`socket(skb->sk)`中，这样的话查找一次`skb`的`socket`就能同时把路由找到。但是这种行为也并非没有负面，就是针对包转发的情况，`skb`是只需要查询路由的，因此在默认情况下，增加的`ip_early_demux`导致转发包也会在查找路由前查找一次`socket`从而导致转发效率降低。
> 默认此特性是打开的，可以直接查看下`sysctl net.ipv4.ip_early_demux`


外界传来的包一般都会满足如上的条件，这样进入到判断后的逻辑中，获取到上层的协议后找到对应的`early_demux`函数。
```
  int protocol = iph->protocol;
  ipprot = rcu_dereference(inet_protos[protocol]);
  if (ipprot && (edemux = READ_ONCE(ipprot->early_demux))) {
```
例如`tcp`就是`6`，`udp`是`17`，假设此包是`tcp`包的话那么对应的函数就是`tcp_v4_early_demux`，逻辑很简单就是查找到`established`的`sock`，然后将其中的路由项赋值到`skb->_skb_refdst`，接着就是校验路由项，如果这儿没有的话就进入到查路由的流程，再去设置路由缓存项。


接着再根据路由缓存项作各种判断，基本就是判断路由类型和数据包类型之类的，最后调用`dst_input`函数，这个函数的具体调用也取决于路由缓存
```
static inline int dst_input(struct sk_buff *skb)
{
 return skb_dst(skb)->input(skb);
}
```
这些因为跳过了路由缓存查找过程，但是如果跟如看的话主要是`ip_route_input_slow`这个函数来实现，如果这个包是发往本地的，调用函数是`ip_local_deliver`，相同的是这儿也有关于`netfilter`的钩子，因此排除这部分后最终调用的函数是`ip_local_deliver_finish`。
挑出重点的逻辑赋值如下：
```
int protocol = ip_hdr(skb)->protocol;
const struct net_protocol *ipprot;
ipprot = rcu_dereference(inet_protos[protocol]);
ret = ipprot->handler(skb);
```
还是向先前的情况一样，如果是`tcp`的话`ipprot`指向的是`tcp_protocol`，那调用函数就是`tcp_v4_rcv`，同理`udp`就是`udp_rcv`。


# `UDP layer`
> 因为`udp`比较简单，所以写`udp`的，反正逻辑差不了太多


剪裁校验完包信息后，先是调用`skb_steal_sock`去尝试获取一下先前`early_demux`设置的`sock`，这儿我们假设是第一次收到信息，那么就进入到`__udp4_lib_lookup_skb`的逻辑中，具体的就不说了，就是根据`目的IP`和`目的端口`找到对应的`socket`，找到的话就设置一下，没找到的话一路返回`err`然后丢弃掉。
> 不过这个函数很有意思，通过端口信息和地址信息查找到`socket`的信息，应该能够用在很多地方，比如在底层的`恶意程序`检测上，从万千`socket`中精确的查找到对应的那一条并`kill`掉。


查找到后用`udp_queue_rcv_skb`来处理报文，碰到如下两种情况就把包丢了：
1. 队列满了
2. 包不满足`filter`


都没啥问题的话就把数据包放在`socket`接收队列的队尾然后通知到`socket`
```
 if (!sock_flag(sk, SOCK_DEAD))
  sk->sk_data_ready(sk);
```


# `Socket layer`
既然是通知了，那实际上在用户态下也要有个数据的接收方式。
1. 通过`recvfrom`阻塞等待数据到来
2. 通过`epoll`或者`select`监听指定的`socket`，最后也是调用到`recvfrom`


> 不管用户态是`recv`还是`recvfrom`在系统调用后面都是`__sys_recvfrom`


关于`netfilter`相关的知识的话，只记录点简单的。
`netfilter`有5个`hook`点，分别是:
1. NF_IP_PRE_ROUTING：刚刚进入网络层，还未进行路由查找的包，通过此处。
2. NF_IP_POST_ROUTING：进入网络层已经经过路由查找，确定转发，将要离开本设备的包，通过此处。

3. NF_IP_LOCAL_IN：通过路由查找，确定发往本机的包，通过此处。

4. NF_IP_LOCAL_OUT：从本机进程刚发出的包，通过此处。

5. NF_IP_FORWARD：经路由查找后，要转发的包，在POST_ROUTING之前。



就像先前的代码流程中看到的，数据包的接收流程中会有`HOOK`函数执行的流程，执行完后才是进入到逻辑函数中，`HOOK`函数中又有既定的规则，这些规则通常来源于`INPUT`，`OUTPUT`，`FORWARD`三条链表中，根据这些规则决定如何处理这些数据包，例如丢弃掉，例如转发。而这些规则呢是由系统管理员认为配置的，因此用户态就有了`iptables`这个工具，能够针对链表规则进行`增删改查`。


# 参考文章
* [Linux网络 - 数据包的接收过程](https://blog.csdn.net/lishanmin11/article/details/77162070)
* [Linux RPS/RFS实现](http://www.cnhalo.net/2016/10/15/linux-rps-rfs/)
* [Linux中rps/rfs的原理及实现](https://tqr.ink/2017/07/09/implementation-of-rps-and-rfs/)
* [设备收发包之netif_receive_skb](http://www.linuxtcpipstack.com/163.html)
* [IP/TCP/UDP中Checksum的计算](http://www.voidcn.com/article/p-htnclmhf-wq.html)

* [monitoring-tuning-linux-networking-stack-receiving-data](https://colobu.com/2019/12/09/monitoring-tuning-linux-networking-stack-receiving-data/)
* [参数ip_early_demux](http://abcdxyzk.github.io/blog/2018/07/09/kernel-ip_early_demux/)
* [Linux协议栈函数调用流程](https://www.cnblogs.com/super-king/p/3284795.html)
* [根据linux内核源码查找recv返回EBADF(errno 9)的原因](https://blog.csdn.net/u012377333/article/details/40890003)
* [利用netfilter截获、修改数据包基础与实现](https://www.jianshu.com/p/8bf6284e832b)
* [iptables介绍iptables和netfilter](https://www.cnblogs.com/benjamin77/p/8630295.html)