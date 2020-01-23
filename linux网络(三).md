网络驱动的编写实际挺简单的，因为要适配各种各样的硬件环境，所以都有相应的开发框架。
既然是网络驱动，就必须要先实现一个设备出来
```
struct net_device *myeth0_dev;
```
为这个设备分配内存
```
myeth0_dev = alloc_netdev(0, "myeth0", NET_NAME_UNKNOWN, ether_setup);
```
> 这是`4.x`内核的写法，可能在低版本下出问题，会提示多传了一个参数，就是`NET_NAME_UNKNOWN`，去掉就行。


为网络设备设置方法，这点是必不可少的一步，如果少了这个，会直接导致内核因为空指针而崩溃掉。
```
static struct net_device_ops myeth0_ops =
{
        .ndo_init = myeth0_dev_init,
        .ndo_start_xmit = myeth0_xmit,
        .ndo_open = myeth0_open,
        .ndo_stop = myeth0_stop,
};
myeth0_dev->netdev_ops = &myeth0_ops;
```
关于几个方法的含义：
1. `ndo_init`：设备初始化时候调用
2. `ndo_start_xmit`：数据报文发送时调用
3. `ndo_open`：启用设备，例如`ifconfig up`时候会调用
4. `ndo_stop`：停止设备时候调用


> 只是写个框架出来的话，可以先全都设置返回值为`0`


注册该设备
```
int err;
err = register_netdev(myeth0_dev);
```
之后插入内核模块后就可以看到这个网驱了。
demo:
```
#include <linux/kernel.h>
#include <linux/jiffies.h>
#include <linux/module.h>
#include <linux/interrupt.h>
#include <linux/fs.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/socket.h>
#include <linux/errno.h>
#include <linux/fcntl.h>
#include <linux/in.h>


#include <linux/uaccess.h>
#include <linux/io.h>


#include <linux/inet.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/skbuff.h>
#include <linux/ethtool.h>
#include <net/sock.h>
#include <net/checksum.h>
#include <linux/if_ether.h> /* For the statistics structure. */
#include <linux/if_arp.h> /* For ARPHRD_ETHER */
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/percpu.h>
#include <linux/net_tstamp.h>
#include <net/net_namespace.h>
#include <linux/u64_stats_sync.h>


static struct net_device *myeth0_dev;
static int myeth0_dev_init (struct net_device *dev)
{
 return 0;
}
static int myeth0_xmit (struct sk_buff *skb, struct net_device *dev)
{
 return 0;
}
static int myeth0_open (struct net_device *dev)
{
 return 0;
}
static int myeth0_stop (struct net_device *dev)
{
 return 0;
}
static struct net_device_ops myeth0_ops =
{
 .ndo_init = myeth0_dev_init,
 .ndo_start_xmit = myeth0_xmit,
 .ndo_open = myeth0_open,
 .ndo_stop = myeth0_stop,
};
static int __init myeth0_init(void)
{
 int err;
 myeth0_dev = alloc_netdev(0, "myeth0", NET_NAME_UNKNOWN, ether_setup);
 if (myeth0_dev == NULL)
  return -ENOMEM;
 myeth0_dev->netdev_ops = &myeth0_ops;
 err = register_netdev(myeth0_dev);
 return err;
}
static void __exit myeth0_exit(void)
{
 unregister_netdev(myeth0_dev);
 free_netdev(myeth0_dev);
}
module_init(myeth0_init);
module_exit(myeth0_exit);
MODULE_AUTHOR("lang");
MODULE_LICENSE("GPL v2");
```
# `kernel`到`netdev`
一个独立的网卡驱动制作完了，那么`kernel`是如何调用的呢？回顾到之前看到的，进入到网络设备调用的最后一个函数是`dev_queue_xmit`。
那自这个函数开始一直到网卡驱动的自定义函数`myeth0_xmit`的调用流程追踪如下：
`dev_queue_xmit`直接就是`return`的`__dev_queue_xmit`，不过其上有一串注释值得注意
```
 * I notice this method can also return errors from the queue disciplines,
 * including NET_XMIT_DROP, which is a positive value. So, errors can also
 * be positive. //这一点主要涉及到函数返回值，简单来说就是skb有可能会因为网络拥塞而被drop，而此刻的返回值是NET_XMIT_DROP这是一个0x01是个正数，因此上层调用需要注意一下函数返回值的判断和处理
 *
 * Regardless of the return value, the skb is consumed, so it is currently
 * difficult to retry a send to this method. (You can bump the ref count
 * before sending to hold a reference for retry if you are careful.)
 *//其实不管返回值，传入的skb都会被消费掉，上层不应当再尝试重发，开发人员的推荐是加入计数引用用来作为参考
 * When calling this method, interrupts MUST be enabled. This is because
 * the BH enable code must have IRQs enabled so that it will not deadlock. //调用此函数的话中断必须打开，这主要还是为了避免死锁问题
 * --BLG
```
这个函数的处理逻辑主要分为两部分，一个是出现`拥塞`情况，一个是普通状况，主要的判断依据如下：
```
txq = netdev_pick_tx(dev, skb, accel_priv); //选择设备的发送队列
q = rcu_dereference_bh(txq->qdisc);
 trace_net_dev_queue(skb);
 if (q->enqueue) {
  rc = __dev_xmit_skb(skb, q, dev, txq);
  goto out;
 }
```
`txq->qdisc`是一个调度器，也可以称为`排队规则`(linux默认的规则是`FIFO`)，决定了数据包进入队列的顺序，倘若此时有`enqueue`规则话，就会直接进入到`拥塞`的flow中，调用`__dev_xmit_skb`，如果没有的话则说明无法进行`拥塞控制`，则在判断设备时候在`UP`状态且`txq`处于`On`状态后通过`dev_hard_start_xmit`函数发送数据。


# `拥塞控制`
> 其实不管有没有拥塞，最后的数据包都是通过调用`dev_hard_start_xmit`发送出去的


首先关于`拥塞控制`实际上应该是每一个真实设备应该具有的，但是技术上总有例外，就像代码中的注释所说的：
```
The device has no queue. Common case for software devices:
loopback, all the sorts of tunnels...
```
简单来说就是`loopback`等`虚拟设备`都没有`qdisc`，并非绝对没有，而是存在并不合理，但是即时是存在`qdisc`就会走`enqueue`的处理吗？其实不是的，进到`__dev_xmit_skb`这个`拥塞控制`函数中，会先判断一下`qdisc`的`state`，如果是`__QDISC_STATE_DEACTIVATED`表示当前设备已经被`close`了，那将会直接返回一个`NET_XMIT_DROP`表示丢弃了这个包，但如果当前满足如下三种情况：
1. `q->flags`是`TCQ_F_CAN_BYPASS`，这个默认条件是可以的
2. `qlen`即队列长度为0，那么当前的`skb`理应是第一个`skb`
3. `qdisc`本来是非`running`的状态，现在成功置位`Running`


如果条件全满足的话就通过`sch_direct_xmit`直接发送这个`skb`，接着如果队列中中还有`skb`的话通过`dequeue`发送，没有的话则直接结束，但总之都是调用的`dev_hard_start_xmit`。这种情况实际上来说就是网络畅通，所以不会造成队列拥堵的情况，直接就传给`dev`了。
如果网络拥堵的话，一般来说就是`qlen!=0`，无论如何需要把`state`设置成`Running`，然后进行`enqueue`操作。
`dev_hard_start_xmit`这个函数就是一个循环发送`skb`的过程，通过调用`xmit_one`来不断发送`skb`，直到遍历完这个链表。跟入到`xmit_one`嵌套了好几层函数，大概的调用流程如下：
> 这儿插一句，抓包工具的核心逻辑就是在这个函数中进行操作的


`xmit_one` -> `netdev_start_xmit` -> `__netdev_start_xmit` -> `ops->ndo_start_xmit`
最后的这个操作函数就是网卡中定义好的函数，负责如何发送数据。


# 参考资料
* [Linux上的物理网卡与虚拟网络设备](https://www.lijiaocn.com/%E6%8A%80%E5%B7%A7/2017/03/31/linux-net-devices.html)
* [Linux内核报文收发-网卡部分](https://zhaozhanxu.com/2016/07/12/Linux/2016-07-12-Linux-Kernel-Pkts_Processing1/)
* [Linux Traffic Control](https://www.ffutop.com/posts/2019-08-23-traffic-control/)
* [IgH(IgH EtherCAT Master for Linux)編譯之linux Debian篇](https://www.itread01.com/content/1546723295.html)
* [内核网络设备的注册与初始化(eth0...)](http://abcdxyzk.github.io/blog/2015/03/27/kernel-net-netdevice/)
* [Linux network and Network access layer](http://wiki.dreamrunner.org/public_html/Linux/Networks/nework-access-layer.html)
* [dpdk 内核模块 Unknown symbol in module 问题](https://www.codeleading.com/article/79591249408/)
* [Which is the correct way to register a new net_device?](https://stackoverflow.com/questions/6726939/which-is-the-correct-way-to-register-a-new-net-device)
* [26.Linux-网卡驱动介绍以及制作虚拟网卡驱动(详解)](https://cloud.tencent.com/developer/article/1012362)
* [Linux驱动程序之网卡驱动(一)](http://www.voidcn.com/article/p-mdyrxmtc-ts.html)
* [Linux网络之设备接口层:发送数据包流程dev_queue_xmit](https://blog.csdn.net/wdscq1234/article/details/51926808)
* [Linux XPS实现](http://www.cnhalo.net/2016/10/14/linux-xps/)
* [linux Qdisc实现](http://www.cnhalo.net/2016/08/13/linux-qdisc/)
* [网卡驱动收发包过程](https://blog.csdn.net/hz5034/article/details/79794615)
* [Linux网络 - 数据包的接收过程](https://segmentfault.com/a/1190000008836467)