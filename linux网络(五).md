> 不讨论其余的，只谈网桥和设备对，因为linux网络实在是太难太恶心了。


# `veth-pair`
如同`tun/tap`一般，这也是虚拟设备，但是却也不同，`tun/tap`的一端是协议栈，一端是用户态程序，然而`veth-pair`是成对出现的，一端连接着协议栈，一端连接彼此。
这个特性很抽象，那就不得不说明一下这个设备的诞生缘由与目的。
```
DESCRIPTION
       The veth devices are virtual Ethernet devices. They can act as tunnels be‐
       tween network namespaces to create a bridge to a physical network device in
       another namespace, but can also be used as standalone network devices.
```
这是`man`手册中的介绍，直接了当地说明了这样的设备对是用来充当不同`network namesapce`之间的`tunnel`的。
`network namespace`是实现网络虚拟化的功能，不同的`namespace`中有各自的`网卡`，`路由表`，`ARP表`，`iptables`等网络资源，就比如在你的系统中创建一个新的`network namespace`后，它的网络就和你系统的网络隔离开了，成了一个独立的网络空间，而`linux`则提供了`veth-pair`将两个`namespace`连通起来，两个空间可以通过这样的一条管道进行网络通信。


做个实验看下，首先建立一个`network namespace`。
```
sudo ip netns add net1 
```
然后创建出`veth-pair`
```
sudo ip link add type veth
```
把其中一个`veth`放到`net1`中
```
sudo ip link set veth1 netns net1
```
分别给两张网卡配置`IP`后启用起来。
```
//主ns
sudo ifconfig veth0 99.1.1.1/24
sudo ifconfig veth0 up
sudo ifconfig
//ns1
sudo ip netns exec net1 ifconfig veth1 99.1.1.2/24
sudo ip netns exec net1 ifconfig veth1 up
sudo ip netns exec net1 ifconfig

```
在`net1`里发个包试试
```
ping -c 1 99.1.1.1
```
但如果在`net1`中添加这么一条路由表后，然后`ping 8.8.8.8`再去抓取`veth0`的数据包，会发现很有意思的事。
```
route add -net 0.0.0.0 netmask 0.0.0.0 gw 99.1.1.2 dev veth1
```
倘若我们物理机上开启了转发功能的话，是否就代表着`net1`真的能够访问外网了呢？
> [Netruon 理解（11）：使用 NAT 将 Linux network namespace 连接外网](https://www.cnblogs.com/sammyliu/p/5760125.html)


# `linux bridge`
`网桥`设备可以理解成是一个虚拟交换机，有若干入口，也有若干出口，而网桥的作用就是在一个口接受到报文时原样复制到其余的各个口，且发送出去，当然为了避免不必要的网络交互产生，交换机经过`地址学习`后能够只向特定的网口发送数据。


实际上对于`veth-pair`来说，就是提供了一种方法让超过两个`network namespace`能够通信，实现的方式就是`veth`的一个在`namespace`中，另一个在网桥上。


至于访问外网，都得开启转发。


# 参考文档
* [linux 网络虚拟化： network namespace 简介](https://cizixs.com/2017/02/10/network-virtualization-network-namespace/)
* [一文搞懂 Linux network namespace](https://www.cnblogs.com/bakari/p/10443484.html)
* [Linux 虚拟网络设备 veth-pair 详解，看这一篇就够了](https://www.cnblogs.com/bakari/p/10613710.html)
* [Linux-虚拟网络设备-veth pair](https://blog.csdn.net/sld880311/article/details/77650937)
* [Linux 虚拟网络设备详解之 Bridge 网桥](https://www.cnblogs.com/bakari/p/10529575.html)
* [linux网桥浅析](https://www.cnblogs.com/morphling/p/3458546.html)
* [linux网桥--简介](https://blog.csdn.net/City_of_skey/article/details/85240141)
* [linux 网络虚拟化： ipvlan](https://cizixs.com/2017/02/17/network-virtualization-ipvlan/)
* [图解几个与Linux网络虚拟化相关的虚拟网卡-VETH/MACVLAN/MACVTAP/IPVLAN](https://blog.csdn.net/dog250/article/details/45788279)
* [Macvlan与ipvlan解析](http://ljchen.net/2018/06/24/macvlan%E4%B8%8Eipvlan%E8%A7%A3%E6%9E%90/)