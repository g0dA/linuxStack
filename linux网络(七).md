# 引言
> 以e1000为例的内核收包流程


还是因为项目需求，需要优化收发包的逻辑那么就得对原生的网卡收包流程有所了解，大部分个人PC的默认驱动都是`e1000/e1000e`，因此就以`e1000`为例子来熟悉一下数据包的接收流程。一个驱动的使用实质上分为三个阶段：
1. 初始化阶段
2. 启动阶段
3. 工作阶段(收发包阶段)


# 驱动初始化
`e1000_init_module`是加载驱动程序时调用的第一个函数，其主要的作用是向`PCI`子系统注册让`主设备`能够通过`pci总线`访问到网卡
```
static int __init e1000_init_module(void)
{
    int ret;
    ....
    ret = pci_register_driver(&e1000_driver);
    ....
    return ret;
}
module_init(e1000_init_module);
```
需要关注的是`&e1000_deiver`这个驱动实例的内容如下
```
static struct pci_driver e1000_driver = {
    .name     = e1000_driver_name,
    .id_table = e1000_pci_tbl,
    .probe    = e1000_probe, //插入操作
    .remove   = e1000_remove, //移除操作
    .driver = {
        .pm = &e1000_pm_ops, //唤醒和暂停操作
    },
    .shutdown = e1000_shutdown, //关闭操作
    .err_handler = &e1000_err_handler
};
```
可以明显的看出这个驱动实例类似于一个操作集，定义了驱动在不同操作下的函数逻辑，而当`pci`检测到一个驱动被新插入到总线上时就会调用到`.probe`指向的函数逻辑即`e1000_probe`对设备进行初始化操作。这是一段相当长的代码，但是如果关注的只是关于内存的使用以及相应操作函数的设置的话，就可以跳过很多一部分直接来到如下部分：
```
    /* there is a workaround being applied below that limits
     * 64-bit DMA addresses to 64-bit hardware.  There are some
     * 32-bit adapters that Tx hang when given 64-bit DMA addresses
     */
    pci_using_dac = 0; //是否可以64位硬件
    if ((hw->bus_type == e1000_bus_type_pcix) &&
        !dma_set_mask_and_coherent(&pdev->dev, DMA_BIT_MASK(64))) {
        pci_using_dac = 1;
    } else {
        err = dma_set_mask_and_coherent(&pdev->dev, DMA_BIT_MASK(32));
        if (err) {
            pr_err("No usable DMA config, aborting\n");
            goto err_dma;
        }
    }
    netdev->netdev_ops = &e1000_netdev_ops;
    e1000_set_ethtool_ops(netdev);
    ....
    netif_napi_add(netdev, &adapter->napi, e1000_clean, 64);
    ....
    if (pci_using_dac) {
        netdev->features |= NETIF_F_HIGHDMA;
        netdev->vlan_features |= NETIF_F_HIGHDMA;
    }
```
这部分的逻辑主要是根据`arch`设置`DMA`掩码，`dma_set_mask_and_coherent`设置了`dma_mask`和`coherent_dma_mask`的值，前者代表了该设备通过`DMA`方式可寻址的物理地址范围，而后者则表示所有设备通过`DMA`方式可寻址的公共物理地址范围，这是因为不是所有的硬件设备都支持到`64bit`的地址宽度的。越过中间的函数设置后面说，先看看最下面的这个条件判断的逻辑，倘若能够使用`64位`硬件，则将当前网络设备的`features`和`vlan_features`都设置成`NETIF_F_HIGHDMA`，即当前设备可以通过`DMA`访问到高地址内存，不过到这为止其实都是针对内存的访问规则的设计还是没有真正的内存分配。
说回中间那段函数设置，其中也包括了两部分，前者设置了设备的操作函数，而后者则初始化了设备的`napi`，先说前者可以看到如下操作集中的函数指针，这都是针对该设备的操作，看清楚这儿是设备操作集合，而之前那个是驱动操作集合，这是两回事。
```
static const struct net_device_ops e1000_netdev_ops = {
    .ndo_open        = e1000_open,
    .ndo_stop        = e1000_close,
    .ndo_start_xmit        = e1000_xmit_frame,
    .ndo_set_rx_mode    = e1000_set_rx_mode,
    .ndo_set_mac_address    = e1000_set_mac,
    .ndo_tx_timeout        = e1000_tx_timeout,
    .ndo_change_mtu        = e1000_change_mtu,
    .ndo_do_ioctl        = e1000_ioctl,
    .ndo_validate_addr    = eth_validate_addr,
    .ndo_vlan_rx_add_vid    = e1000_vlan_rx_add_vid,
    .ndo_vlan_rx_kill_vid    = e1000_vlan_rx_kill_vid,
#ifdef CONFIG_NET_POLL_CONTROLLER
    .ndo_poll_controller    = e1000_netpoll,
#endif
    .ndo_fix_features    = e1000_fix_features,
    .ndo_set_features    = e1000_set_features,
};
```
继续说`NAPI`机制，简单的来说就是在这个机制诞生以前，`cpu`针对网卡数据包的处理都得依靠网卡发起`硬中断`来反应，随之带来的问题就是当千兆网卡的使用导致每秒产生数千个中断使得`cpu`完全把精力放在了处理`中断`上让系统处于一种`忙碌状态`，而对于包处理的能力被极大的限制从而导致大量丢包。而采用了`NAPI`的机制后，则驱动只是通过`硬中断`通知到`cpu`有数据包，在中断上下文外使用轮询的方式一次性接受多个包处理，这本质上是通过`硬中断`唤醒数据接收程序来处理数据包：
1. 非`NAPI`：数据包-硬中断-包处理
2. `NAPI`：数据包-硬中断-禁用硬中断且轮询-包处理


那话说回来就是怎么通过`硬中断`怎么去禁用网卡`硬中断`并通知到数据接收程序开始轮寻呢？这个要等到`工作阶段`才能被用到因此按下不表。


# 启动阶段
驱动初始化中创建了一个设备，那这个设备自然需要被用户态打开后才能使用，比如使用`ifconfig`或者是`iproute`等工具，而这些都是触发`初始化阶段`中设置的`设备操作集`中的`.ndo_open`即`e1000_open`函数逻辑，这个函数本质上也是一个初始化过程，只不过是设备初始化，不过其中就涉及到了内存分配的过程，也就是设备的`ring buffer`的初始化。
```
    /* allocate transmit descriptors */
    err = e1000_setup_all_tx_resources(adapter);
    if (err)
        goto err_setup_tx;


    /* allocate receive descriptors */
    err = e1000_setup_all_rx_resources(adapter);
    if (err)
        goto err_setup_rx;
```
上面的代码初始化`tx环形队列`和`rx环形队列`，而为什么说是全部呢？因为现在的`cpu`基本都是多核的，而这个`环形队列`是一个`核`一个，因此才是`all_*_resources`，跟进去看逻辑的话也就是一个`for循环`，核心函数还是`e1000_setup_*_resources`
```
/**
 * e1000_setup_rx_resources - allocate Rx resources (Descriptors)
 * @adapter: board private structure
 * @rxdr:    rx descriptor ring (for a specific queue) to setup
 *
 * Returns 0 on success, negative on failure
 **/
int e1000_setup_all_rx_resources(struct e1000_adapter *adapter)
{
    int i, err = 0;


    for (i = 0; i < adapter->num_rx_queues; i++) {
        err = e1000_setup_rx_resources(adapter, &adapter->rx_ring[i]);
        if (err) {
            e_err(probe, "Allocation for Rx Queue %u failed\n", i);
            for (i-- ; i >= 0; i--)
                e1000_free_rx_resources(adapter,
                            &adapter->rx_ring[i]);
            break;
        }
    }
    return err;
}
```
跟入函数中可以看到调用了`dma_alloc_coherent`分配了一个`一致性DMA`内存
```
    /* Round up to nearest 4K */


    rxdr->size = rxdr->count * desc_len;
    rxdr->size = ALIGN(rxdr->size, 4096);


    rxdr->desc = dma_alloc_coherent(&pdev->dev, rxdr->size, &rxdr->dma,
                    GFP_KERNEL);
```
这个函数它其实会返回两个地址，`rxdr->desc`是`DMA`区域的虚拟地址，而`&rxdr->dma`则是物理地址，而`rxdr`本身则是一个`e1000_rx_ring`的结构体也就是`环形缓冲区`本身，但是他本质上却是一个`descriptor`队列。
```
struct e1000_rx_ring {
    /* pointer to the descriptor ring memory */
    void *desc;
    /* physical address of the descriptor ring */
    dma_addr_t dma;
    /* length of descriptor ring in bytes */
    unsigned int size;
    /* number of descriptors in the ring */
    unsigned int count;
    /* next descriptor to associate a buffer with */
    unsigned int next_to_use;
    /* next descriptor to check for DD status bit */
    unsigned int next_to_clean;
    /* array of buffer information structs */
    struct e1000_rx_buffer *buffer_info;
    struct sk_buff *rx_skb_top;  //分片包里的第一个包
    /* cpu for rx queue */
    int cpu;
    u16 rdh;
    u16 rdt;
};
```
当缓冲区建立好以后，则调用`mmset`全部清零内存区域，这儿需要重点关注一下`*buffer_info`这个对象，后面将会有大作用，当环形缓冲区建立好以后需要配置网卡参数还有注册网卡中断。
```
    e1000_configure(adapter);


    err = e1000_request_irq(adapter);
    if (err)
        goto err_req_irq;
```
前者主要在于寄存器的初始化和一些函数初始化，稍微需要关注的大概就只有其中的`e1000_configure_*`会初始化几个在后续的`收发包流程`里会用到的函数，比如`adapter->clean_rx = e1000_clean_rx_irq`，然后有个比较重要的点在于这一段代码：
```
    /* call E1000_DESC_UNUSED which always leaves
     * at least 1 descriptor unused to make sure
     * next_to_use != next_to_clean
     */
    for (i = 0; i < adapter->num_rx_queues; i++) {
        struct e1000_rx_ring *ring = &adapter->rx_ring[i];
        adapter->alloc_rx_buf(adapter, ring,
                      E1000_DESC_UNUSED(ring));
    }
```
`adapter->alloc_rx_buf`在上面的配置中默认下对应的函数是`e1000_alloc_rx_buffers`，注释上有写到这个函数的作用是`Replace used receive buffers`
```
    data = e1000_alloc_frag(adapter);
    ....
    buffer_info->dma = dma_map_single(&pdev->dev,
                          data,
                          adapter->rx_buffer_len,
                          DMA_FROM_DEVICE);
    ....
    buffer_info->rxbuf.data = data;  
```
但是实际上来说，函数充当了最初数据包区域的初始化，上述的`环形队列`实际上是一个个的`descriptor`而非数据包本身，那么自然需要再申请一块区域用来存放数据包并和`buffer_info`这个指针关联上，而且同样是用到的`DMA`方式复制的数据因此在这儿用的是`流式DMA内存`的申请方式，而`dma_map_single`则是为`buffer_info`建立`DMA映射`。
而`e1000_request_irq`注册中断的逻辑其中写的很直白，注册的中断函数是`e1000_intr`
```
static int e1000_request_irq(struct e1000_adapter *adapter)
{
    struct net_device *netdev = adapter->netdev;
    irq_handler_t handler = e1000_intr;
    int irq_flags = IRQF_SHARED;
    int err;
    err = request_irq(adapter->pdev->irq, handler, irq_flags, netdev->name,
              netdev);
    if (err) {
        e_err(probe, "Unable to allocate interrupt Error: %d\n", err);
    }
    return err;
}
```
进去看一看这个函数。
```
    /* disable interrupts, without the synchronize_irq bit */
    ew32(IMC, ~0);
    E1000_WRITE_FLUSH();


    if (likely(napi_schedule_prep(&adapter->napi))) {
        adapter->total_tx_bytes = 0;
        adapter->total_tx_packets = 0;
        adapter->total_rx_bytes = 0;
        adapter->total_rx_packets = 0;
        __napi_schedule(&adapter->napi);
    } else {
        /* this really should not happen! if it does it is basically a
         * bug, but not a hard error, so enable ints and continue
         */
        if (!test_bit(__E1000_DOWN, &adapter->flags))
            e1000_irq_enable(adapter);
    }
```
和`NAPI`机制中阐述的完全一致，先禁用掉`irq`后再调用到`napi_schedule`执行`&adpater->napi`，这个在先前的驱动初始化中被设置成了`e1000_clean`，那意思就是会调用到`e1000_clean`。
```
/**
 * e1000_clean - NAPI Rx polling callback
 * @napi: napi struct containing references to driver info
 * @budget: budget given to driver for receive packets
 **/
static int e1000_clean(struct napi_struct *napi, int budget)
```


# 工作阶段
先回顾前面两个阶段的内容：
1. 硬中断函数：`e1000_intr`
2. NAPI回调函数：`e1000_clean`


> 硬件层的逻辑是硬件负责的，而非依靠驱动负责，比如发起`硬中断`，比如`DMA`复制数据，在收包的流程里，驱动是在硬中断之后才会参与其中，而这个时候报文数据其实已经躺到了内核内存里。


`CPU`接收到网卡的`硬中断`后调用`e1000_intr`来调用`__napi_schedule`执行`NAPI回调函数`
```
void __napi_schedule(struct napi_struct *n)
{
    unsigned long flags;


    local_irq_save(flags);
    ____napi_schedule(this_cpu_ptr(&softnet_data), n);
    local_irq_restore(flags);
}
EXPORT_SYMBOL(__napi_schedule);
/* Called with irq disabled */
static inline void ____napi_schedule(struct softnet_data *sd,
                     struct napi_struct *napi)
{
    list_add_tail(&napi->poll_list, &sd->poll_list);
    __raise_softirq_irqoff(NET_RX_SOFTIRQ);
}
```
可以看到`__napi_schedule`的主要逻辑就是将一个`napi_struct`放到了一个`poll_list`中，并且设置了`NET_RX_SOFTIRQ`触发一个软中断，而软中断函数就是之前设置的回调函数`e1000_clean`
> 可以看到在函数注释上就说明了在此期间需要把`irq`禁用


现在来看一下`e1000_clean`的具体逻辑
```
static int e1000_clean(struct napi_struct *napi, int budget)
{
    struct e1000_adapter *adapter = container_of(napi, struct e1000_adapter,
                             napi);
    int tx_clean_complete = 0, work_done = 0;


    tx_clean_complete = e1000_clean_tx_irq(adapter, &adapter->tx_ring[0]);


    adapter->clean_rx(adapter, &adapter->rx_ring[0], &work_done, budget);


    if (!tx_clean_complete || work_done == budget)
        return budget;


    /* Exit the polling mode, but don't re-enable interrupts if stack might
     * poll us due to busy-polling
     */
    if (likely(napi_complete_done(napi, work_done))) {
        if (likely(adapter->itr_setting & 3))
            e1000_set_itr(adapter);
        if (!test_bit(__E1000_DOWN, &adapter->flags))
            e1000_irq_enable(adapter);
    }
    return work_done;
}
```
针对收包的部分主要还是调用的`adapter->clean_rx`来处理，这个在配置网卡的时候会配置这个函数
```
    if (adapter->netdev->mtu > ETH_DATA_LEN) {
        rdlen = adapter->rx_ring[0].count *
            sizeof(struct e1000_rx_desc);
        adapter->clean_rx = e1000_clean_jumbo_rx_irq;
        adapter->alloc_rx_buf = e1000_alloc_jumbo_rx_buffers;
    } else {
        rdlen = adapter->rx_ring[0].count *
            sizeof(struct e1000_rx_desc);
        adapter->clean_rx = e1000_clean_rx_irq;
        adapter->alloc_rx_buf = e1000_alloc_rx_buffers;
    }
```
默认情况下主要还是`e1000_clean_rx_irq`，这个函数的作用就是把接收到的数据发送到协议栈上，因此这儿的工作实际上就是把`buffer_info`的数据封装到`skb`中再向上层发送，主要的函数实现是`e1000_copybreak`
```
/* this should improve performance for small packets with large amounts
 * of reassembly being done in the stack
 */
static struct sk_buff *e1000_copybreak(struct e1000_adapter *adapter,
                       struct e1000_rx_buffer *buffer_info,
                       u32 length, const void *data)
{
    struct sk_buff *skb;
    if (length > copybreak)
        return NULL;
    skb = e1000_alloc_rx_skb(adapter, length);
    if (!skb)
        return NULL;
    dma_sync_single_for_cpu(&adapter->pdev->dev, buffer_info->dma,
                length, DMA_FROM_DEVICE);


    skb_put_data(skb, data, length);


    return skb;
}
```
其中`dma_sync_single_for_cpu`是在`流式DMA`下需要驱动主动保证`cache一致性`的一种操作。


# 参考文章
* [Linux kernel 帧的接收](https://www.daimajiaoliu.com/daima/4796bd284900405)
* [LINUX网络子系统中DMA机制的实现](https://club.perfma.com/article/663987)
* [Linux协议栈--NAPI机制](http://cxd2014.github.io/2017/10/15/linux-napi/)