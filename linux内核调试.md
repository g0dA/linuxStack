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


# 参考
* [使用QEMU和GDB調試Linux內核](https://hk.saowen.com/a/799c1e179f9d301206d4e2a9845917ab88839e21a6187cc63d2cb54d633e5684)
* [QEMU+gdb调试Linux内核全过程](https://blog.csdn.net/jasonLee_lijiaqi/article/details/80967912)
* [学习ulk3,搭建linux2.6内核的调试环境](https://zhuanlan.zhihu.com/p/35180950)