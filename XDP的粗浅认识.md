# 引言
> 最近在搞流量检测，在DPDK和XDP中负责XDP的部分，结果就开始被折磨


说原理不如直接上代码，以`4.9`的`mlx5`驱动为例子看`xdp`是怎么融入其中的，用这一个版本是因为这是`mlx5`驱动刚支持`xdp`的版本。说起`xdp`很多资料都会说它快都是因为其工作在`DMA`之后`skb`之前，但是在实际流程上来说这个时间区间里其实还做了大量的工作，而`xdp`的插入则是真正的到了`skb`的前一步才被处理:
```
skb = skb_from_cqe(rq, cqe, wqe_counter, cqe_bcnt);
```
这是在接收数据包环节中分配`skb`的代码，跟进去就可以看到`xdp`的流程被插入在了这份代码之中
```
dma_sync_single_range_for_cpu(rq->pdev,
                  di->addr,
                  MLX5_RX_HEADROOM,
                  rq->buff.wqe_sz,
                  DMA_FROM_DEVICE);
prefetch(data);


if (unlikely((cqe->op_own >> 4) != MLX5_CQE_RESP_SEND)) {
    rq->stats.wqe_err++;
    mlx5e_page_release(rq, di, true);
    return NULL;
}


if (mlx5e_xdp_handle(rq, xdp_prog, di, data, cqe_bcnt))
    return NULL; /* page/packet was consumed by XDP */


skb = build_skb(va, RQ_PAGE_SIZE(rq));
```
可以看到倘若`mlx5e_xdp_handle`返回一个`true`就会跳过下面的`buile_skb`的流程，那这个函数的实现如下：
```
/* returns true if packet was consumed by xdp */
static inline bool mlx5e_xdp_handle(struct mlx5e_rq *rq,
                    const struct bpf_prog *prog,
                    struct mlx5e_dma_info *di,
                    void *data, u16 len)
{
    struct xdp_buff xdp;
    u32 act;


    if (!prog)
        return false;


    xdp.data = data;
    xdp.data_end = xdp.data + len;
    act = bpf_prog_run_xdp(prog, &xdp);
    switch (act) {
    case XDP_PASS:
        return false;
    case XDP_TX:
        mlx5e_xmit_xdp_frame(rq, di, MLX5_RX_HEADROOM, len);
        return true;
    default:
        bpf_warn_invalid_xdp_action(act);
    case XDP_ABORTED:
    case XDP_DROP:
        rq->stats.xdp_drop++;
        mlx5e_page_release(rq, di, true);
        return true;
    }
}
```
`XDP_PASS`会返回一个`false`那么一个数据包将依然会进入到`build_skb`和`put_skb`的流程里，那就说明`XDP_PASS`并不能带来性能上的优势，反观`XDP_DROP`则是直接进行了`release`并且返回`true`从而跳过了后续的流程，因此才会十分的快速。


# 使用
`xdp`本质上是通过`ebpf`实现的在包处理路径中插入的针对数据包的预处理能力，那用法自然还是脱离不了常规的`bpf`用法，这点可以参考`bcc`或者是`kernel demo`
* [bcc Reference Guide](https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md)
* [linux/samples/bpf/](https://github.com/torvalds/linux/tree/master/samples/bpf)


一个简单的`xdp`的使用包含了三部分：
1. 逻辑代码
2. 加载器
3. 数据交互


就说逻辑代码本身来说就是针对数据包的处理，例如一个针对`ip`的解析
```
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/types.h>

SEC("xdp")
int xdpinit(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if ((void *)eth + sizeof(struct ethhdr) <= data_end) {
        struct iphdr *ip = data + sizeof(*eth);
        if ((void *)ip + sizeof(struct iphdr) <= data_end) {
            return XDP_DROP;
         } 
    } else {
        bpf_trace_printk(\"eth is error\\n\");
    }
    return XDP_PASS;
}
char _license[] SEC("license") = "GPL";
```
逻辑代码本身并不难写，但是代码被`ebpf`所限制，因此在实际使用起来功能其实有限的很，比如支持的能力可以参照这个列表：
* [BPF Features by Linux Kernel Version](https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md#xdp)


接下来说加载器，`xdp`代码需要依靠`clang/llvm`编译完成，这两个东西其实我都不怎么熟悉不做讲解，单就最终编译出来的`*.o`文件来说，需要依靠加载器将其加载到驱动上去，最简洁的加载方式是通过`ip link`来加载
```
sudo ip link set dev eth0 xdp obj xdp.o
```
通过这种方式加载`xdp字节码`来完成使用，然而带来的问题就是不够灵活，因此在实际使用中常用的加载方式还是:
1. C
2. bcc(python)


二者都有常规的加载框架，前者可以参考`kernel/samples`，而后者则不需要开发者关注编译上的事情做到了写完就能用的地步，两者都为`bpf`的开发带来的极大的便利。因此在整个`xdp`的使用上最大的痛苦来源实际是`数据交互`的部分。


# BPF MAP
简单来说就是`bpf`程序并不能任意的`kmalloc`内存，而是得通过`bpf map`来使用内存，同时这个内存区域也承担了`数据通信`的作用，而内存布局也依靠不同版本的内核提供的`type`来决定，这块区域统称为一个`map`，而就是针对这块内存区域，从`create`到`lookup`到`update`到`delete`都有种种底层逻辑限制，而这些限制可能并没有用户态的详细说明这就导致在实际开发中很有可能遇到种种问题。。


