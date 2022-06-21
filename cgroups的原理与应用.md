> 疫情以来一直是居家办公，确实是很久都没有好好研究东西了，cgroups作为容器侧的两大基石本该是很早以前就被研究的东西，但是因为种种原因吧就一直拖延到了22年才加入到笔记里面


# `Cgroups`和`Container`
在现在看来，`Cgroups`是`Container`的基石之一，但是在2007年那个容器技术还不是很成熟的时代`Cgroup`却就是`Container`本身，因为其最初被设计出来的用法就是被用作容器化进程的，甚至是连名字都是`Process containers`
> 管中窥豹，可见一斑


可以从最初的`Porcess container`上来探究未来的`Cgroups`的设计模式，在内核中引入了一些新的概念，其中比较重要的一个叫做`子系统(subsystem)`，比如内核中原本存在的`cpusets`这种用于绑定进程的机制就被变成了一种`子系统`，而其余的一些`子系统`也都是类似的原本关注于资源管理的一些机制，然后还有一个`container`的概念代表的是一组使用了相同`子系统`配置的进程，再就是`container`是分层的且配置是可继承的，因为它用了一个`group`的形式来管理进程所以在最初的`patch`提交的时候设计者还在其中探讨了是否需要把这个系统重新命名一下比如`ProcessSets? ResourceGroups? TaskGroups?`
> simple hierarchy

![[容器层次结构]](./cgroups的原理与应用_files/0a579ab2-4ca6-43fb-a1dc-cd3583bf6141.png)


在如上的图中，`Guests`和`Sys tasks`就是两个容器，用到了不同的设置的进程会运行在其中，倘若有些`Guests`下的一些进程想要更进一步地进行配置，那就会在`Guests`的基础上再创建出具有特定策略的新容器出来，例如`G1`,`G2`,`G3`


伴随着`子系统`在`container`中应用相应的还有随之配套的一些基础规则产生：
1. 一个层级结构可以关联上一个或者多个子系统
2. 一个子系统只能关联到一个层结构上
3. 在有多个层次结构时进程就会同时处于多个容器中，至少每个层级结构中有一个 ，但是相同的层级中一个进程只能出现在一个容器里


在设计上`container`的使用并不是通过提供内核`ABI`或是`Library`的形式方便代码直接调用，而是选用了`VFS`来作为用户接口，用户在挂载对应的文件系统后通过对文件的操作来实现`container`的创建，这种做法极大的降低了操作的难度并且使得配置可视化方便了使用者


那么重新以现在的视角来审视最初的设计模式，`Process container`的容器概念不像是如今的`container`而更像是`k8s`中`pod`的概念，其在设计上注重的就并非是`隔离(isloation)`而是`资源管理(resource management)`，原本的`container`变成了现在的`cgroup`，不同的`cgroup`有着不同的`子系统`配置并且其中跑着`task`，而这些`cgroup`组成了树状结构就是`hierarchy`，而一个系统中可以有多个`hierarchy`，这些就是`Cgroups`整个概念的抽象表现
```
➜  ~ mount -t cgroup
cgroup on /sys/fs/cgroup/systemd type cgroup (rw,nosuid,nodev,noexec,relatime,seclabel,xattr,release_agent=/usr/lib/systemd/systemd-cgroups-agent,name=systemd)
cgroup on /sys/fs/cgroup/pids type cgroup (rw,nosuid,nodev,noexec,relatime,seclabel,pids)
cgroup on /sys/fs/cgroup/perf_event type cgroup (rw,nosuid,nodev,noexec,relatime,seclabel,perf_event)
cgroup on /sys/fs/cgroup/net_cls,net_prio type cgroup (rw,nosuid,nodev,noexec,relatime,seclabel,net_prio,net_cls)
cgroup on /sys/fs/cgroup/cpuset type cgroup (rw,nosuid,nodev,noexec,relatime,seclabel,cpuset)
cgroup on /sys/fs/cgroup/hugetlb type cgroup (rw,nosuid,nodev,noexec,relatime,seclabel,hugetlb)
cgroup on /sys/fs/cgroup/freezer type cgroup (rw,nosuid,nodev,noexec,relatime,seclabel,freezer)
cgroup on /sys/fs/cgroup/blkio type cgroup (rw,nosuid,nodev,noexec,relatime,seclabel,blkio)
cgroup on /sys/fs/cgroup/devices type cgroup (rw,nosuid,nodev,noexec,relatime,seclabel,devices)
cgroup on /sys/fs/cgroup/memory type cgroup (rw,nosuid,nodev,noexec,relatime,seclabel,memory)
cgroup on /sys/fs/cgroup/cpu,cpuacct type cgroup (rw,nosuid,nodev,noexec,relatime,seclabel,cpuacct,cpu)
```
这是现代操作系统中`cgroups v1`的一个最典型的使用，从上述的挂载信息中就可以看出来系统在启动的时候就初始化了11个`hierarchy`并且分别关联了不同的`子系统`，这样当你需要去针对不同的资源进行控制的时候就只需要到对应的目录中创建新的`cgroup`，实际也就是一个目录然后再把指定的进程放进去就可以了


# 从进程中去看
当然上面的都是从用户态去观察`cgroup`，然而实质运用上来说最小的单位依旧是一个`进程`也就是一个`task`，那么在内核中是怎么知道一个`task`被怎么限制的资源呢？像`cgroups`这种内核中的运用非常广泛的大机制一般都会有一个专门的结构体来负责然后再作为进程`task_struct`的一个基础成员
```
struct task_struct {
······
#ifdef CONFIG_CGROUPS
    /* Control Group info protected by css_set_lock */
    struct css_set __rcu *cgroups;
    /* cg_list protected by css_set_lock and tsk->alloc_lock */
    struct list_head cg_list;
#endif
······
}
```
一般一个进程没有经过特殊处理的话默认都会处于系统的初始`cgroups`之中
```
crash> task -R cgroups 3555
PID: 3555   TASK: ffff880207fb4380  CPU: 1   COMMAND: "zsh"
  cgroups = 0xffff880223a0ce00
```
该`cgroups`由内核初始化时候创建
```
/**
 * cgroup_init - cgroup initialization
 *
 * Register cgroup filesystem and /proc file, and initialize
 * any subsystems that didn't request early init.
 */
int __init cgroup_init(void)
```
该函数会初始化填充`subsys`整个数组，为了便于管理一般来说初始化的`cgroups`都是和全部的`子系统`都有关联
```
crash> css_set.subsys 0xffff880223a0ce00
  subsys = {
                    0xffffffff81c7f640 <top_cpuset>, 
                    0xffffffff81ff4d40 <root_task_group>, 
                    0xffffffff81c535a0 <root_cpuacct>, 
                    0xffffffff822472a0 <blkcg_root>, 
                    0xffff88017fc1c000, 
                    0xffff88023128e000, 
                    0xffff88017fc3fbc0, 
                    0xffff88017fc3fc80, 
                    0xffff88017fc3fd40, 
                    0xffff88017fc0d000, 
                    0xffff88023128c900
}
```
如果把进程加入到某个新的`cgroup`当中，那么进程的`cgroups`就会变掉
```
~ /sys/fs/cgroup/devices/test  sudo sh -c 'echo 3555 > cgroup.procs'


crash> task -R cgroups 3555
PID: 3555   TASK: ffff880207fb4380  CPU: 3   COMMAND: "zsh"
  cgroups = 0xffff880207f09600, 


crash> css_set.subsys 0xffff880207f09600
  subsys = {0xffff880033380800, 0xffffffff81ff4d40 <root_task_group>, 0xffffffff81c535a0 <root_cpuacct>, 0xffffffff822472a0 <blkcg_root>, 0xffff88017fc1c000, 0xffff8800bb333600, 0xffff88017fc3fbc0, 0xffff88017fc3fc80, 0xffff88017fc3fd40, 0xffff88017fc0d000, 0xffff88023128c900}
```
而后这些限制如何被内核所落实那就是组调度来负责实现的，这是另一个知识点暂且按下不表


# `v1` VS `v2`
在`Kernel 4.5`以后`Cgroups v2`被正式加入到了内核，它与`v1`相比有了极大的变化，最典型的一个就是针对`hierarchy`的简化，`v1`为了灵活性不同的`子系统`分成了不同的`hierarchy`，需要控制进程的某个资源就到相应的`hierarchy`中创建子节点然后将进程添加进去，这是没有任何限制的因此当控制需求逐渐增多就会变得愈发混乱，第二点就是`v1`允许了线程划分到不同的`cgroup`中，但是这些线程都是共享的相同的进程资源，这使得`memory`的资源控制变得没有意义


`v2`的改进：
1. Cgroups v2 中所有的 controller 都会被挂载到一个 unified hierarchy 下，不在存在像 v1 中允许不同的 controller 挂载到不同的 hierarchy 的情况
2. Proess 只能绑定到 cgroup 的根(“/“)目录和 cgroup 目录树中的叶子节点
3. 通过 cgroup.controllers 和 cgroup.subtree_control 指定哪些 controller 可以被使用
4. v1 版本中的 task 文件和 cpuset controller 中的 cgroup.clone_children 文件被移除
5. 当 cgroup 为空时的通知机制得到改进，通过 cgroup.events 文件通知


# 安全问题
在`cgroups`上出现的安全问题基本都围绕着如下两个方面:
1. `devices`
2. `release_agent`


前者主要用于控制`task`能够访问到的设备资源，而后者则是`cgroups`本身的一个清理机制，先说说前者


* 在`v1`之中存在一个`devices.allow`，其中决定了`task`能够访问到设备，在容器这种隔离的环境下，如果该文件被重写使得容器中的进程能够访问到整个主机磁盘设备的话，就可以通过新建设备文件然后重挂载或者`debugfs`的方式进行磁盘读写造成容器逃逸


该技术只需要解决以下几个难点即可：
1. `devices.allow`的内容格式是`type major:minor access`只需要写入`a *:* rwm`即可，但是`mknod`是需要知道明确的`major:minor`的，这点在真实环境中需要自己去找
2. 在正常情况下`cgroup`的目录都是只读挂载的，因此需要有写入权限才能被利用


但是很可惜的是，到了`v2`当中`device controllers`被移除了，在·unified hierarchy·中不再提供接口文件而是在`cgroup bpf`基础上实现访问控制，管理者需要通过编写`BPF_PROG_TYPE_CGROUP_DEVICE`类型的`BPF`程序然后`attach`到指定的`cgroup`且类型指定为`BPF_CGROUP_DEVICE`，进程访问设备触发`BPF`程序来决定是否允许访问


再说说`release_agent`，这本身是`cgroup`的一个清理机制，主要用途就是当`cgroup`中不再有进程的时候就可以触发执行用于清除整个`cgroup`目录或是做其余一些收尾的事情，当然如果想要触发的话就需要在`notify_on_release`中设置为`1`，但是这个机制很容易被滥用，因为其底层原始实际上是在内核中调用了`call_usermodehelper()`也就是在内核态执行用户态的程序权限是十分高的，当`release_agent`的内容可以随意修改的话就很容易遭到利用


在早期的版本中`release_agent`的写入检查就仅仅是`root`即可而没有正确检查写入进程是否具有`CAP_SYS_ADMIN`权限，直接导致了当`cgroup`被以读写形式挂载到容器当中时可以轻而易举的形成逃逸，当然这个问题在`CVE-2022-0492`被提交以后就被修补了，但是`release_agent`依然还是在提权思路中一个经久不衰的`tips`


# 结语
今年因为种种特殊原因很久没有接触技术类的东西了，导致刚开始几天看起文章和资料来相当的乏力，因此这篇关于`cgroups`的内容还是存在着种种的不足，比如`调度问题`上都被一带而过，比如`v2`上其实都没有做任何的实际阐述，更比如`安全性`上仅仅是举了`cgroups`两个人尽皆知的例子而没有加入任何自己的思考，这种归纳状态无疑是不正确的


牢骚无需多言，如果有什么需要探讨的东西，可以随时联系我 : )


# 参考资料
* [Process containers](https://lwn.net/Articles/236038/)
* [一篇搞懂容器技术的基石： cgroup](https://segmentfault.com/a/1190000040980305)
* [Linux资源管理之cgroups简介](https://tech.meituan.com/2015/03/31/cgroups.html)
* [第一千零一篇的-cgroups-介紹-](https://medium.com/starbugs/%E7%AC%AC%E4%B8%80%E5%8D%83%E9%9B%B6%E4%B8%80%E7%AF%87%E7%9A%84-cgroups-%E4%BB%8B%E7%B4%B9-a1c5005be88c)
* [容器核心:cgroups](https://www.jianshu.com/p/052e3d5792ee)
* [cgroup源码分析1—— css_set和cgroup的关系](http://linux.laoqinren.net/kernel/cgroup-source-css_set-and-cgroup/)
* [小张学linux内核：四.cgroup子系统和组调度](https://blog.csdn.net/qq_40036519/article/details/105902367)
* [Linux 内核调度器源码分析 - 初始化](https://segmentfault.com/a/1190000039999292#item-2-6)
* [cgroups_v2-LCA2019](https://man7.org/conf/lca2019/cgroups_v2-LCA2019-Kerrisk.pdf)
* [LXCCGroupV2](https://wiki.debian.org/LXC/CGroupV2)
* [cgroup-v2](https://www.kernel.org/doc/html/v5.10/admin-guide/cgroup-v2.html)
