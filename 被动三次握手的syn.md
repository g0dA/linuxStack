# 引言
完全项目相关的调研的东西，而且也加深网络理解因此记录一下，主要在于调研内核是如何处理`syn`请求藉此研究如何能够针对性的防御住`syn flood`


# 处理`syn`
这个分为两种情况：
1. 源IP发送的第一个`syn`
2. 源IP发送的第N个`syn`


两者都是由`tcp_v4_rcv`函数来处理，而其中的逻辑分叉点在于如下逻辑
```
int tcp_v4_rcv(struct sk_buff *skb)
{
    ........
    th = (const struct tcphdr *)skb->data;
    iph = ip_hdr(skb);
lookup:
    sk = __inet_lookup_skb(&tcp_hashinfo, skb, __tcp_hdrlen(th), th->source,
                   th->dest, sdif, &refcounted);
    if (!sk)
        goto no_tcp_socket;


process:
    if (sk->sk_state == TCP_TIME_WAIT)
        goto do_time_wait;


    if (sk->sk_state == TCP_NEW_SYN_RECV) {
        struct request_sock *req = inet_reqsk(sk);
    ........
}
```
`__inet_lookup_skb`会查询当前报文是否是已经建立的连接
```
static inline struct sock *__inet_lookup_skb(struct inet_hashinfo *hashinfo,
                         struct sk_buff *skb,
                         int doff,
                         const __be16 sport,
                         const __be16 dport,
                         const int sdif,
                         bool *refcounted)
{
    struct sock *sk = skb_steal_sock(skb, refcounted);
    const struct iphdr *iph = ip_hdr(skb);


    if (sk)
        return sk;


    return __inet_lookup(dev_net(skb_dst(skb)->dev), hashinfo, skb,
                 doff, iph->saddr, sport,
                 iph->daddr, dport, inet_iif(skb), sdif,
                 refcounted);
}


static inline struct sock *__inet_lookup(struct net *net,
                     struct inet_hashinfo *hashinfo,
                     struct sk_buff *skb, int doff,
                     const __be32 saddr, const __be16 sport,
                     const __be32 daddr, const __be16 dport,
                     const int dif, const int sdif,
                     bool *refcounted)
{
    u16 hnum = ntohs(dport);
    struct sock *sk;


    sk = __inet_lookup_established(net, hashinfo, saddr, sport,
                       daddr, hnum, dif, sdif);
    *refcounted = true;
    if (sk)
        return sk;
    *refcounted = false;
    return __inet_lookup_listener(net, hashinfo, skb, doff, saddr,
                      sport, daddr, hnum, dif, sdif);
}
```
看上面的流程会先检测`skb->sk`不过这个不影响大局，而是直接进入到`inet_lookup`的流程里，其中的主要方法就是根据本地和远程的地址端口信息先从`ehash`中查找`socket`，如果没有的话则从`lhash`中查找到，如果都没有的话则进入到`no_tcp_socket`标签流程里面去，这个流程主要在于校验一下`checksum`合法性然后发送`reset`报文，重新回到分支的地方，就是找到了`socket`查找里，如果服务是通过`listen`而正常启动的话则是状态为`TCP_LISTEN`，这个在先前的`inet_listen`会被初始化，那么则进入到`tcp_v4_do_rcv`的流程中：
```
    if (sk->sk_state == TCP_LISTEN) {
        ret = tcp_v4_do_rcv(sk, skb);
        goto put_and_return;
    }
```
这个函数因为会被多个地方调用，因此针对目前的情况只看第一种：
```
    if (sk->sk_state == TCP_LISTEN) {
        struct sock *nsk = tcp_v4_cookie_check(sk, skb);


        if (!nsk)
            goto discard;
        if (nsk != sk) {
            if (tcp_child_process(sk, nsk, skb)) {
                rsk = nsk;
                goto reset;
            }
            return 0;
        }
    } else
        sock_rps_save_rxhash(sk, skb);


    if (tcp_rcv_state_process(sk, skb)) {
        rsk = sk;
        goto reset;
    }
    return 0;


reset:
    tcp_v4_send_reset(rsk, skb);
discard:
    kfree_skb(skb);
    /* Be careful here. If this function gets more complicated and
     * gcc suffers from register pressure on the x86, sk (in %ebx)
     * might be destroyed here. This current version compiles correctly,
     * but you have been warned.
     */
    return 0;
```
其中`nsk = tcp_v4_cookie_check`这个主要是进行`syn cookie`检查的，这个针对`syn`单包不置位因此这部分直接越过进入到`tcp_rcv_state_process`中，依然只关注到其中`TCP_LISTEN`的部分
```
    case TCP_LISTEN:
        if (th->ack)
            return 1;


        if (th->rst)
            goto discard;


        if (th->syn) {
            if (th->fin)
                goto discard;
            /* It is possible that we process SYN packets from backlog,
             * so we need to make sure to disable BH and RCU right there.
             */
            rcu_read_lock();
            local_bh_disable();
            acceptable = icsk->icsk_af_ops->conn_request(sk, skb) >= 0;
            local_bh_enable();
            rcu_read_unlock();


            if (!acceptable)
                return 1;
            consume_skb(skb);
            return 0;
        }
        goto discard;
```
看逻辑不接收`ack`丢弃`rst`，然后在针对`syn`的处理中丢弃`fin`，添加`rcu`读锁，然后进入到连接请求处理的环节，这儿的函数指针指向的是`tcp_v4_conn_request`
```
int tcp_v4_conn_request(struct sock *sk, struct sk_buff *skb)
{
    /* Never answer to SYNs send to broadcast or multicast */
    if (skb_rtable(skb)->rt_flags & (RTCF_BROADCAST | RTCF_MULTICAST))
        goto drop;


    return tcp_conn_request(&tcp_request_sock_ops,
                &tcp_request_sock_ipv4_ops, sk, skb);


drop:
    tcp_listendrop(sk);
    return 0;
}
EXPORT_SYMBOL(tcp_v4_conn_request);
```
如果是发向广播或者组播的直接丢弃，否则进入`tcp_conn_request`环节，忽略掉`syn cookies`和`fastopen`的东西核心代码如下：
检测全连接数量`sk_ack_backlog`是否大于上限，如果到达上限则直接丢弃
```
    if (sk_acceptq_is_full(sk)) {
        NET_INC_STATS(sock_net(sk), LINUX_MIB_LISTENOVERFLOWS);
        goto drop;
    }
```
分配请求控制块，同时将连接状态修改为`TCP_NEW_SYN_RECV`，这儿要明确注意的一点是，此刻被修改了连接的是`req`而不是`sk`，`req`可以理解成是内核维护的一个轻量级`sock`，而`req->rsk_listener`才是原本的`sk`所以对于连接本身来说此时其实还是处于`listen`状态的。
```
    req = inet_reqsk_alloc(rsk_ops, sk, !want_cookie);
    if (!req)
        goto drop;
```
将`req`加入到`ehash`中且设置了重传定时器，然后发送`syn ack`
> 默认的重试次数是5次，然后时间间隔是`1s + 2s + 4s+ 8s+ 16s + 32s = 63s`


```
if (!want_cookie)
        inet_csk_reqsk_queue_hash_add(sk, req,
            tcp_timeout_init((struct sock *)req));
af_ops->send_synack(sk, dst, &fl, req, &foc,
                    !want_cookie ? TCP_SYNACK_NORMAL :
                           TCP_SYNACK_COOKIE,
                    skb);
```
这儿就是需要注意的加入`ehash`和超时重传的操作需要跟进看一看。
```
void inet_csk_reqsk_queue_hash_add(struct sock *sk, struct request_sock *req,
                   unsigned long timeout)
{
    reqsk_queue_hash_req(req, timeout);
    inet_csk_reqsk_queue_added(sk);  //原子加法增加了队列数量，用于统计没有重传过synack的请求数
}
```
前者就是关键的将`sock`插入到`ehash`中，主要逻辑是根据四元组作hash且其中有自旋锁的操作。
```
    spin_lock(lock);
        __sk_nulls_add_node_rcu(sk, list);
    spin_unlock(lock);
```
这个hash表中`req`会在收到`ACK`后会被取出最终加入到`accpet`队列中也就是常说的全连接队列，以上的针对收到单个`SYN`的情况，那么如果是同一IP持续不断的发送`syn`是怎么处理的呢？这个得重新回到刚才的逻辑判断的地方也就是如下：
```
sk = __inet_lookup_skb(&tcp_hashinfo, skb, __tcp_hdrlen(th), th->source,
                   th->dest, sdif, &refcounted);
```
`__inet_lookup_skb`这是一个查询现有连接的操作，倘若四元组完全一致的话则会从`ehash`中找到这个处于半连接状态的`sock`，而且状态为`TCP_NEW_SYN_RECV`，否则会当作是首个`syn`对待然后走先前的流程。一般来说`TCP_NEW_SYN_RECV`的流程里期待收到的是一个`ACK`用来完成三次握手建立正式连接，但是如果继续收到的是一个`syn`会怎么办？
这一点完全在`tcp_check_req`中被检查到了：
```
    /* Check for pure retransmitted SYN. */
    if (TCP_SKB_CB(skb)->seq == tcp_rsk(req)->rcv_isn &&
        flg == TCP_FLAG_SYN &&
        !paws_reject) {
        /*
         * RFC793 draws (Incorrectly! It was fixed in RFC1122)
         * this case on figure 6 and figure 8, but formal
         * protocol description says NOTHING.
         * To be more exact, it says that we should send ACK,
         * because this segment (at least, if it has no data)
         * is out of window.
         *
         *  CONCLUSION: RFC793 (even with RFC1122) DOES NOT
         *  describe SYN-RECV state. All the description
         *  is wrong, we cannot believe to it and should
         *  rely only on common sense and implementation
         *  experience.
         *
         * Enforce "SYN-ACK" according to figure 8, figure 6
         * of RFC793, fixed by RFC1122.
         *
         * Note that even if there is new data in the SYN packet
         * they will be thrown away too.
         *
         * Reset timer after retransmitting SYNACK, similar to
         * the idea of fast retransmit in recovery.
         */
        if (!tcp_oow_rate_limited(sock_net(sk), skb,
                      LINUX_MIB_TCPACKSKIPPEDSYNRECV,
                      &tcp_rsk(req)->last_oow_ack_time) &&


            !inet_rtx_syn_ack(sk, req)) {
            unsigned long expires = jiffies;


            expires += min(TCP_TIMEOUT_INIT << req->num_timeout,
                       TCP_RTO_MAX);
            if (!fastopen)
                mod_timer_pending(&req->rsk_timer, expires);
            else
                req->rsk_timer.expires = expires;
        }
        return NULL;
    }
```
虽然中间有一堆逻辑，但是实际上来说就是返回`NULL`，这就导致外部中的逻辑会直接把新的`syn`给丢弃掉不处理。
最后再说下一个已经处于`ESTABLISHED`状态的连接如果收到`syn`会怎样？这个会越过大部分代码直接进入如下流程：
```
    if (!sock_owned_by_user(sk)) {
        skb_to_free = sk->sk_rx_skb_cache;
        sk->sk_rx_skb_cache = NULL;
        ret = tcp_v4_do_rcv(sk, skb);
    } else {
        if (tcp_add_backlog(sk, skb))
            goto discard_and_relse;
        skb_to_free = NULL;
    }
```
这个主要是看用户进程是否持锁，但是最终都还是到了`tcp_v4_do_rcv`中进行处理最终调用的是`tcp_rcv_established`
```
    if (sk->sk_state == TCP_ESTABLISHED) { /* Fast path */
        struct dst_entry *dst = sk->sk_rx_dst;


        sock_rps_save_rxhash(sk, skb);
        sk_mark_napi_id(sk, skb);
        if (dst) {
            if (inet_sk(sk)->rx_dst_ifindex != skb->skb_iif ||
                !dst->ops->check(dst, 0)) {
                dst_release(dst);
                sk->sk_rx_dst = NULL;
            }
        }
        tcp_rcv_established(sk, skb);
        return 0;
    }
```
进入到`slow path`的处理流程里，其中有一个合法性校验`tcp_validate_incoming`其中有一个`syn_challenge`的部分：
```
    /* step 3: check security and precedence [ignored] */


    /* step 4: Check for a SYN
     * RFC 5961 4.2 : Send a challenge ack
     */
    if (th->syn) {
syn_challenge:
        if (syn_inerr)
            TCP_INC_STATS(sock_net(sk), TCP_MIB_INERRS);
        NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPSYNCHALLENGE);
        tcp_send_challenge_ack(sk, skb);
        goto discard;
    }
```
直接发了一个`ack`出去
> RFC 5961 提出了 ACK Throttling 方案，限制了每秒钟发送 Challenge ACK 报文的数量，这个值由 net.ipv4.tcp_challenge_ack_limit 系统变量决定，默认值是 1000。




# 参考资料
* [关于TCP同时打开-无需Listener的TCP连接建立过程](https://blog.csdn.net/dog250/article/details/80518481)
* [新版本linux内核SYN队列和accept队列的真正实现方式](https://blog.csdn.net/z530234020/article/details/114981573)
* [硬不硬你说了算！近 40 张图解被问千百遍的 TCP 三次握手和四次挥手面试题](https://www.huaweicloud.com/articles/b6d3104d1faee8f1ae7584899be7bbba.html)
* [ESTABLISHED 状态的连接收到 SYN 会回复什么？](https://juejin.cn/post/6844904081387945997)
* [linux-tcp-prequeue-backlog](http://www.cnhalo.net/2016/07/13/linux-tcp-prequeue-backlog/)
