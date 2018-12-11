> audit是一种system，内核态的东西，而auditctl/auditd是使用audit system的application，是应用程序，用户态的东西

先说应用，这些应用用于linux系统的安全审计，能够将审计的记录写入日志文件，包括各种系统调用信息以及文件访问信息。
## 和syslog的区别
* `syslog`也是linux的日志系统，但是却又和`audit`有区别，`audit`主要是用于记录安全信息，而`syslog`则更杂，记录着各种警报以及软件的日志。
* `syslog`属于应用层，无法记录内核层的信息，`audit`是内核提供的日志时间记录能力，因此可以用来记录内核信息，如文件读写，权限改变，系统调用。
* `syslog`审计实现是内核函数`printk`将各种消息写入一个环境缓冲区，然后提供给上层的`sys_syslog`系统调用读取。而`audit`的实现则是内核其余线程通过`audit API`写入套接字缓冲区队列`audit_skb_queue`里，然后内核线程`kauditd`通过`netlink`将消息定向发送给用户空间的`auditd`的主线程，`auditd`再通过事件队列将消息传给应用的写log线程写入。
## 流程
![image001.png](https://www.ibm.com/developerworks/cn/linux/l-lo-use-space-audit-tool/image001.png)
内核的运行信息都会在`audit`中记录，然后按照规则传输给`auditd`，再有`auditd`进行其余操作，最后写入`log`文件，因为是`netlink`的通信机制，所以无需用户态主动发起请求。

## 主要目的
尽量少的消耗性能监控到系统调用以及各种安全事件，从而提供溯源追踪的能力。

## 参考文档
* [linux服务之audit](https://www.cnblogs.com/createyuan/p/3861149.html)
* [Linux 用户空间审计工具 audit](https://www.ibm.com/developerworks/cn/linux/l-lo-use-space-audit-tool/index.html)
