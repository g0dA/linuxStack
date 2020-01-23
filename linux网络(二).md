> 光知道原理怎么能行，自然需要明白如何落地。说白了，撸代码，写网驱。


在上层协议多种多样，但是最后发送出去的途径就只有通过网卡，而网卡是属于硬件设备，系统中与这个设备对应的接口叫做网卡驱动，通常情况下功能仅限于负责收发网络数据包，这样就引入了一个非常重要的结构体：`sk_buff`，也叫`数据报文`。而关于网卡驱动同样也有一个文件结构体：`net_device`，然后其操作集为：`net_device_ops`


首先要明白的概念是网络的收发由发送队列和接收队列来实现，这是两条链表结构，而每一个表项就是一个`skb`。`skb`是各层之间的通用结构，但是随着层级转换，例如从`传输层`的`TCP`到`网络层`的`IP`，`skb`中的数据会产生变化，这是数据封装这个行为所带来的结果，通过数据的变化引入需要的首部或者偏移等数据。
> 这点如果用`tcp`来说一个函数就可以看出来:tcp_connect()
```
/* Build a SYN and send it off. */
int tcp_connect(struct sock *sk)
{
 struct tcp_sock *tp = tcp_sk(sk);
 struct sk_buff *buff;
 int err;
 tcp_call_bpf(sk, BPF_SOCK_OPS_TCP_CONNECT_CB);
 if (inet_csk(sk)->icsk_af_ops->rebuild_header(sk))
  return -EHOSTUNREACH; /* Routing failure or similar. */
 tcp_connect_init(sk);
 if (unlikely(tp->repair)) {
  tcp_finish_connect(sk, NULL);
  return 0;
 }
 buff = sk_stream_alloc_skb(sk, 0, sk->sk_allocation, true);
......
```


因而如果按照数据结构体来划分的话，自上而下的网络信息可以分为：`socket层`和`协议层`，分别使用的是`struct sock`和`struct sk_buff`来作为网络数据的标识，而`skb`则是在`socket层`创建，在`协议层`流动，在`物理层`消失。
> 关于`skb`本身这个结构体太大了，其中包含了众多指针，但是概括起来就是`head`，`data`，`tail`，`end`


# 数据的发送
从先前的`tcp_connect`说起，在`tcp_v4_connect`中构建好整个`sock`信息后，数据传输到了此函数中开始构建`SYN`的`skb`，其中几个函数很有意思：
1. `tcp_connect_queue_skb`会增加套接口的发送队列统计值`sk_wmem_queued`，即增加发送队列长度，增量为`skb`的`trusize`值，但是没有直接把这个`skb`加入到`sk_write_queue(发送队列)`中
2. `tcp_rbtree_insert`这个函数会把`skb`加入到`tcp_rtx_queue`这个重传队列中，等到发送超时后再从这调用发送


等做完了这些，就会有一个判断`tp->fastopen_req`即`fast open`，`TFO`在`3.13`版本后的内核被默认打开使用(`v6在3.16`)，如果落实到应用层代码的话，就是直接使用`sendto()`或者`sendmsg()`而不使用`connect`，这种连接方式会在客户端保留一个服务端生成并通过`SYN-ACK`发送过来的`cookie`，下次传输时客户端的`SYN`会携带此数据，如果服务端通过验证的话，则在最终的`ack`握手包到来之前就开始发送数据，降低的延迟。但是如果没有使用`TFO`的话，自然会走传统数据传输的道路，也就是`tcp_transmit_skb`。


第一个包是`SYN`包而非常规`TCP数据`
```
 if (unlikely(tcb->tcp_flags & TCPHDR_SYN))
  tcp_options_size = tcp_syn_options(sk, skb, &opts, &md5);
 else
  tcp_options_size = tcp_established_options(sk, skb, &opts,
          &md5);
```
自然在这儿就会走一个`tcp_syn_options`的构建，但是并不重要，整个函数大多是一些数据的构造，哦还有熟悉的`tcp窗口`计算
> 滑动窗口是一种流量控制技术


```
 if (likely(!(tcb->tcp_flags & TCPHDR_SYN))) {
  th->window = htons(tcp_select_window(sk));
  tcp_ecn_send(sk, skb, th, tcp_header_size);
 } else {
  /* RFC1323: The window in SYN & SYN/ACK segments
   * is never scaled.
   */
  th->window = htons(min(tp->rcv_wnd, 65535U));
 }
```
最后把处理完成的`skb`给传到`IP层`去再进一步处理
```
err = icsk->icsk_af_ops->queue_xmit(sk, skb, &inet->cork.fl);
```
这儿的操作函数其实是`ip_queue_xmit`
```
const struct inet_connection_sock_af_ops ipv4_specific = {
 .queue_xmit = ip_queue_xmit,
 .send_check = tcp_v4_send_check,
 .rebuild_header = inet_sk_rebuild_header,
 .sk_rx_dst_set = inet_sk_rx_dst_set,
 .conn_request = tcp_v4_conn_request,
 .syn_recv_sock = tcp_v4_syn_recv_sock,
 .net_header_len = sizeof(struct iphdr),
 .setsockopt = ip_setsockopt,
 .getsockopt = ip_getsockopt,
 .addr2sockaddr = inet_csk_addr2sockaddr,
 .sockaddr_len = sizeof(struct sockaddr_in),
#ifdef CONFIG_COMPAT
 .compat_setsockopt = compat_ip_setsockopt,
 .compat_getsockopt = compat_ip_getsockopt,
#endif
 .mtu_reduced = tcp_v4_mtu_reduced,
};
EXPORT_SYMBOL(ipv4_specific);
```
至于初始化的问题，还要往前到`tcp_v4_init_sock`时候，略过。
先前有整理过各种`tcp_v4_connect`时候的路由问题，最终也没有什么太明确的结果，而在`ip_queue_xmit`中则是优先针对来自上层的`skb`的路由做了处理，而后才是填充`ip层`的结构，最后通过`ip_local_out`发送出去。
```
 rt = skb_rtable(skb);
 if (rt)
  goto packet_routed;
```
直截了当的判断了`tcp路由缓存`有没有被设置，有的话则跳转到`packet_routed`，不过第一次进来时候这儿的`rt`为`0x0`，而真正去检查路由缓存的操作如下：
```
 rt = (struct rtable *)__sk_dst_check(sk, 0);
```
然后将路由设置到`skb`中，就进入到了`packet_routed`的流程：
```
skb_dst_set_noref(skb, &rt->dst);
```
这个流程中基本就是封包了，构造完各种`IP`层需要的数据，最后通过`ip_local_out`再传输到下一层去。


## `ip_local_out`
其中真正的核心发送函数是`dst_output`
```
static inline int dst_output(struct net *net, struct sock *sk, struct sk_buff *skb)
{
 return skb_dst(skb)->output(net, sk, skb);
}
```
这儿实际就是`ip_output`，设置了输出设备和协议，这儿的设备是`lo`，最后调用`ip_finish_output`输出，而关于`ip_finish_output`的作用主要就是对`skb`进行分片，如果上层是`TCP`则不用分片，其中还包含了针对`skb`的`gso`判断，如果是的话则调用`gso`输出，除开这段后最后会调用`ip_finins_output2`。
> 又是一大段知识。


这个函数中会再次丰富`skb`内容，添加`以太网头`(如果不够的话还要重新申请)，最后会在此函数中构建出一条完整可用的报文。
后面又涉及到`邻居子系统`的概念:
```
邻居子系统是从物理来说是指在同一个局域网内的终端。从网络拓扑的结构来说，是指他们之间相隔的距离仅为一跳，他们属于同一个突冲域
发送数据的时候，要在本机进行路由查找，如果有到目的地地址的路径，查看arp缓存中是否存在相应的映射关系，如果没有，则新建邻居项。判断邻居项是否为可用状态。如果不可用。把skb 存至邻居发送对列中，然后将发送arp请求。
如果接收到arp应答。则将对应邻居项置为可用。如果在指定时间内末收到响应包，则将对应邻居项置为无效状态。
如果邻居更改为可用状态，则把邻居项对应的skb对列中的数据包发送出去
```
大概的调用流程为：
```
ip_finish_output2 -> neigh_output -> neigh_hh_output -> dev_queue_xmit
```
到`dev_queue_xmit`开始，数据报文开始进入到`网络驱动`的逻辑之中。


# 参考资料
* [Linux-网卡驱动介绍以及制作虚拟网卡驱动(详解)](https://cloud.tencent.com/developer/article/1012362)
* [sk_buff结构](http://www.mamicode.com/info-detail-2006217.html)
* [Linux内核网卡驱动程序](http://mark-shih.blogspot.com/2011/01/)
* [lwip TCP客户端 tcp_connect函数源码解析](https://blog.csdn.net/guozhongwei1/article/details/50482553)
* [TCP传输队列长度sk_wmem_alloc统计](https://blog.csdn.net/sinat_20184565/article/details/88723621)
* [读Linux内核(4.9.9)之TCP连接三次握手](https://blog.csdn.net/idwtwt/article/details/79339770)
* [linux tcp fastopen实现](http://www.cnhalo.net/2016/06/13/linux-tcp-fastopen/)
* [TCP快速打开](https://zh.wikipedia.org/wiki/TCP%E5%BF%AB%E9%80%9F%E6%89%93%E5%BC%80)
* [TCP的发送系列 — 发送缓存的管理（一）](https://blog.csdn.net/zhangskd/article/details/47862581)
* [TCP发送函数tcp_transmit_skb](https://blog.csdn.net/City_of_skey/article/details/84723087)
* [TCP的窗口](https://www.jianshu.com/p/9f59b937eaf1)
* [TCP协议中的窗口机制------滑动窗口详解](https://blog.csdn.net/m0_37962600/article/details/79951780)
* [TCP->IP输出 之 ip_queue_xmit、ip_build_and_send_pkt、ip_send_unicast_reply](http://www.linuxtcpipstack.com/636.html)
* [理解 Linux 网络栈（2）：非虚拟化Linux 环境中的 Segmentation Offloading 技术](https://www.cnblogs.com/sammyliu/p/5227121.html)
* [理解 TCP/IP 网络栈](https://cizixs.com/2017/07/27/understand-tcp-ip-network-stack/)
* [linux网络协议栈：邻居子系统](http://www.voidcn.com/article/p-vyishcsx-bea.html)