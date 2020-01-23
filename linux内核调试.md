# 环境
> 在坑里很久，用的64位的ubuntu桌面版，一直出问题，很烦，最后换成32位的了，最后发现，问题出在`cp /boot/config-xxxx .config`上，不要执行！！不要执行！！直接`make defconfig`然后`make menuconfig`，不要`cp`！！！


`QEMU`+`GDB`+`busybox`


# QEMU
```
sudo apt-get install qemu
```
# busybox
[源码下载](https://busybox.net/downloads/)


`busybox`的作用就是生成一个简单的`根文件系统`


下载源码后执行：
```
make defconfig
make menuconfig
```
设置下配置，采用静态编译的方式，否则程序运行期间会动态加载库文件。
```
-> Busybox Setting -> Build Options
[*] Build BusyBox as a static binary (no shared libs)
```
保存后可以再确认下，出现的是`CONFIG_STATIC=y`则没什么问题了
```
cat .config| grep STATIC
```
接着就开始编译安装
```
make
make install
```
文件都会生成到`_install`文件夹下，后面的内容借鉴下[QEMU+gdb调试Linux内核全过程](https://blog.csdn.net/jasonLee_lijiaqi/article/details/80967912)，生成`initramfs.img`留备用


# 内核
内核的编译主要得开启`CONFIG_DEBUG_INFO`(有`CONFIG_GDB_SCRIPTS`就也开启，没有就算)
```
Kernel hacking -->
  [*] Kernel debug
  [*] Compile the kernel with debug info


Kernel hacking -->

  [*] compile the kernel with frame pointers


Kernel hacking -->
  [*] KGDB: kernel debugging with remote gdb
```
这样可以看一下`.config`中是否为`CONFIG_DEBUG_INFO=y`和`CONFIG_FRAME_POINTER=y`，之后编译安装内核，会用到生成的`arch/x86_64/boot/bzImage`
> 要注意只设置上面两个，其余全都不选择，否则会出现断点没拦截的情况，也可以尝试取消`Write protect kernel read-only data structures`这个选项，不过没有实验过，还有`b start_kernel`的问题，这个参照下[硬件断点](http://link.zhihu.com/?target=https%3A//bugs.launchpad.net/ubuntu/%2Bsource/qemu-kvm/%2Bbug/901944)




# 调试
> [GEF插件](https://gef.readthedocs.io/en/dev/)


执行命令先把内核运行起来：
```
qemu-system-i386 -kernel /usr/src/linux-2.6.32.1/arch/x86/boot/bzImage -initrd initramfs.img -S -s
```
挂起状态等待`gdb`连接，端口是默认的`1234`
然后开启`gdb`连接，到编译的内核文件目录下执行：
```
gdb vmlinux
(gdb)target remote:1234
(gdb)b cmdline_proc_show   //下个测试断点
(gdb)c
```
此时在`qemu`中执行`cat /proc/cmdline`即可看到断点信息


# VMware+gdb双机调试
这个调试方式比qemu更实用，上面一样的，调试配置都打开，然后可能还涉及一个`CONFIG_DEBUG_RODATA`，低版本可能是`CONFIG_DEBUG_RODATA_TEST`的关闭，不然你的断点没有用。


生成内核镜像后，复制到宿主机的相同路径下，开启GDB:
```
(gdb)>file vmlinux
(gdb)>target remote localhost:8864
```
修改要调试的虚拟机的配置文件
```
vim /tools/centos7/CentOS7/CentOS7.vmx
```
然后添加如下内容：
```
debugStub.listen.guest64 = "TRUE"
debugStub.listen.guest64.remote = "TRUE"
debugStub.hideBreakpoints = "FALSE"
monitor.debugOnStartGuest64 = "TRUE"
```
接着就按照正常的调试方式下断点调试就行，可以先看看`b start_kernel`，但是会存在编译优化的问题，导致断点断错位，因此要降低编译优化，修改`Makefile`
```
ifeq ($(DEBUG),y)
    DEBFLAGS = -O -g3 -DSBULL_DEBUG
else
    DEBFLAGS = -O0
endif
EXTRA_CFLAGS += $(DEBFLAGS)
```
最后就是随机化的问题，`kernel`加载到内存后起始地址随机化，因此调试地址和真实地址不太相同，会导致断点失败，所以需要禁用随机化`kaslr`。
然而内核编译优化的问题依然没有得到解决，在`-O0`的情况下内核无法编译通过，因为`kernel`本身的设计思想中就包含了编译优化的假想，这就导致不优化的情况下大量底层汇编代码根本无法编译通过，那么只能通过`__attribute__((optimize("O0")))`修饰函数来跳过优化了，不过这个方法我没有去尝试，不过编译时候好像有报错，最后还是用打`patch`的方式。


# 参考
* [使用QEMU和GDB調試Linux內核](https://hk.saowen.com/a/799c1e179f9d301206d4e2a9845917ab88839e21a6187cc63d2cb54d633e5684)
* [QEMU+gdb调试Linux内核全过程](https://blog.csdn.net/jasonLee_lijiaqi/article/details/80967912)
* [学习ulk3,搭建linux2.6内核的调试环境](https://zhuanlan.zhihu.com/p/35180950)
* [GDB调试指南-断点设置](https://www.yanbinghu.com/2019/02/24/44483.html)
* [Linux环境下通过Vmware调试内核及模块](https://freemandealer.github.io/2015/03/18/kernel-debugging/)
* [宋宝华： 关于Linux编译优化几个必须掌握的姿势](https://mp.weixin.qq.com/s?__biz=MzAwMDUwNDgxOA==&mid=2652665119&idx=1&sn=15ef70466e254c0d2029ad961be8d32c&chksm=810f3382b678ba943c23fd1d2d0f17cd022cce013af4e20ac148242f46e1172e0237979878d3&scene=27#wechat_redirect&cpage=17)
* [9102年如何来调试内核](https://blog.stdio.io/1086)
* [-Og patch](https://lwn.net/ml/linux-kernel/1525179614-14571-1-git-send-email-changbin.du@intel.com/)