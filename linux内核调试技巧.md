> 关于调试，除开内存之外，离不开的一点就是各类寄存器。


# 寄存器
`x86_64`下的16种通用寄存器
<div class="wiz-table-container" style="position: relative; padding: 0px;" contenteditable="false"><div class="wiz-table-body" contenteditable="true"><table style="width: 1307px;"><thead><tr><th style="width: 64px;">寄存器名</th><th style="width: 647px;">寄存器简介</th><th style="width: 378px;">主要功能</th><th style="width: 51px;">63-0</th><th style="width: 49px;">31-0</th><th style="width: 62px;">15-0</th><th style="width: 55px;">8-0</th></tr></thead><tbody><tr><td style="width: 64px;">rax</td><td style="width: 647px;">累加器，是算术运算的主要寄存器</td><td style="width: 378px;">存储返回值</td><td style="width: 51px;">rax</td><td style="width: 49px;">eax</td><td style="width: 62px;">ax</td><td style="width: 55px;">al</td></tr><tr><td style="width: 64px;">rbx</td><td style="width: 647px;">基址寄存器，被调用者保存</td><td style="width: 378px;">存放存储区的起始地址</td><td style="width: 51px;">rbx</td><td style="width: 49px;">ebx</td><td style="width: 62px;">bx</td><td style="width: 55px;">bl</td></tr><tr><td style="width: 64px;">rcx</td><td style="width: 647px;">计数寄存器</td><td style="width: 378px;">循环操作和字串处理的计数控制；函数调用时的第4个参数</td><td style="width: 51px;">rcx</td><td style="width: 49px;">ecx</td><td style="width: 62px;">cx</td><td style="width: 55px;">cl</td></tr><tr><td style="width: 64px;">rdx</td><td class="" style="width: 647px;"><div>I/O指针</div></td><td style="width: 378px;">I/O操作时提供外部设备接口的端口地址；函数调用时的第3个参数</td><td style="width: 51px;">rdx</td><td style="width: 49px;">edx</td><td style="width: 62px;">dx</td><td style="width: 55px;">dl</td></tr><tr><td style="width: 64px;">rsi</td><td style="width: 647px;">(source index)源变址寄存器，与rds段寄存器联用，可以访问数据段中的任一个存储单元</td><td style="width: 378px;">函数调用时的第2个参数</td><td style="width: 51px;">rsi</td><td style="width: 49px;">esi</td><td style="width: 62px;">si</td><td style="width: 55px;">sil</td></tr><tr><td style="width: 64px;">rdi</td><td class="" style="width: 647px;"><div>(destination index)目的变址寄存器，与res段寄存器联用，可以访问附加段中的任一个存储单元</div></td><td style="width: 378px;">函数调用时的第1个参数</td><td style="width: 51px;">rdi</td><td style="width: 49px;">edi</td><td style="width: 62px;">di</td><td style="width: 55px;">dil</td></tr><tr><td style="width: 64px;">rbp</td><td style="width: 647px;">(base pointer)基址指针寄存器，用于提供堆栈内某个单元的偏移地址，与rss段寄存器联用，可以访问堆栈中的任一个存储单元，被调用者保存</td><td style="width: 378px;"><br></td><td style="width: 51px;">rbp</td><td style="width: 49px;">ebp</td><td style="width: 62px;">bp</td><td style="width: 55px;">bpl</td></tr><tr><td style="width: 64px;">rsp</td><td style="width: 647px;">(stack pointer)栈顶指针寄存器，提供堆栈栈顶单元的偏移地址，与rss段寄存器联用，以控制数据进栈和出栈</td><td style="width: 378px;"><br></td><td style="width: 51px;">rsp</td><td style="width: 49px;">esp</td><td style="width: 62px;">sp</td><td style="width: 55px;">spl</td></tr><tr><td style="width: 64px;">r8</td><td style="width: 647px;"><br></td><td style="width: 378px;">函数调用时的第5个参数</td><td style="width: 51px;">r8</td><td style="width: 49px;">r8d</td><td style="width: 62px;">r8w</td><td style="width: 55px;">r8b</td></tr><tr><td style="width: 64px;">r9</td><td style="width: 647px;"><br></td><td style="width: 378px;">函数调用时的第6个参数</td><td style="width: 51px;">r9</td><td style="width: 49px;">r9d</td><td style="width: 62px;">r9w</td><td style="width: 55px;">r9b</td></tr><tr><td style="width: 64px;">r10</td><td style="width: 647px;">调用者保存</td><td style="width: 378px;"><br></td><td style="width: 51px;">r10</td><td style="width: 49px;">r10d</td><td style="width: 62px;">r10w</td><td style="width: 55px;">r10b</td></tr><tr><td style="width: 64px;">r11</td><td style="width: 647px;">调用者保存</td><td style="width: 378px;"><br></td><td style="width: 51px;">r11</td><td style="width: 49px;">r11d</td><td style="width: 62px;">r11w</td><td style="width: 55px;">r11b</td></tr><tr><td style="width: 64px;">r12</td><td style="width: 647px;">被调用者保存</td><td style="width: 378px;"><br></td><td style="width: 51px;">r12</td><td style="width: 49px;">r12d</td><td style="width: 62px;">r12w</td><td style="width: 55px;">r12b</td></tr><tr><td style="width: 64px;">r13</td><td style="width: 647px;">被调用者保存</td><td style="width: 378px;"><br></td><td style="width: 51px;">r13</td><td style="width: 49px;">r13d</td><td style="width: 62px;">r13w</td><td style="width: 55px;">r13b</td></tr><tr><td style="width: 64px;">r14</td><td style="width: 647px;">被调用者保存</td><td style="width: 378px;"><br></td><td style="width: 51px;">r14</td><td style="width: 49px;">r14d</td><td style="width: 62px;">r14w</td><td style="width: 55px;">r14b</td></tr><tr><td style="width: 64px;">r15</td><td style="width: 647px;">被调用者保存</td><td style="width: 378px;"><br></td><td style="width: 51px;">r15</td><td style="width: 49px;">r15d</td><td style="width: 62px;">r15w</td><td style="width: 55px;" class="">r15b</td></tr></tbody></table></div></div>

段寄存器：
<div class="wiz-table-container" style="position: relative; padding: 0px;" contenteditable="false"><div class="wiz-table-body" contenteditable="true"><table style="width: 468px;"><thead><tr><th style="width: 142px;" class="">寄存器</th><th style="width: 325px;" class="">功能</th></tr></thead><tbody><tr><td style="width: 142px;" class="">CS(code segment)</td><td class="" style="width: 325px;"><div>代码段地址寄存器，存放代码段的起始地址</div></td></tr><tr><td style="width: 142px;" class="">DS(data segment)</td><td style="width: 325px;" class="">数据段地址寄存器，存放数据段的起始地址</td></tr><tr><td style="width: 142px;" class="">SS(stack segment)</td><td style="width: 325px;" class="">堆栈段地址寄存器，存放堆栈段的起始地址</td></tr><tr><td style="width: 142px;" class="">ES(extra segment)</td><td style="width: 325px;" class=""><div>附加段地址寄存器，存放附加段的起始地址</div></td></tr></tbody></table></div></div>

控制寄存器
<div class="wiz-table-container" style="position: relative; padding: 0px;" contenteditable="false"><div class="wiz-table-body" contenteditable="true"><table style="width: 488px;"><tbody><tr><th colspan="1" rowspan="1" style="width: 142px;" class=""><div>寄存器</div></th> <th colspan="1" rowspan="1" style="width: 345px;">功能</th></tr><tr><td colspan="1" rowspan="1" style="width:142px;" class=""><div>Cr0</div></td> <td colspan="1" rowspan="1" style="width: 345px;" class=""><div>存放控制处理器操作模式和状态的系统控制标志</div></td></tr><tr><td colspan="1" rowspan="1" style="width:142px;" class=""><div><span style="">Cr1</span><br></div></td> <td colspan="1" rowspan="1" style="width: 345px;" class=""><div>保留</div></td></tr><tr><td colspan="1" rowspan="1" style="width:142px;" class=""><div><span style="">Cr2</span><br></div></td> <td colspan="1" rowspan="1" style="width: 345px;" class=""><div>存放导致页错误的线性地址</div></td></tr><tr><td colspan="1" rowspan="1" style="width:142px;" class=""><div><span style="">Cr3</span><br></div></td> <td colspan="1" rowspan="1" style="width: 345px;" class=""><div>存放页目录表基地址</div></td></tr><tr><td class="" style="width: 142px;"><div>Cr4</div></td><td style="width: 345px;" class=""><div>处理器扩展功能标志位</div></td></tr><tr><td style="width: 142px;" class=""><div>Cr8</div></td><td style="width: 345px;" class=""><div>当前lrql权限等级</div></td></tr></tbody></table></div></div>



# `CONFIG_STRICT_DEVMEM`
现在内核基本都开了这个编译选项，导致调式的时候根本无法修改内存
```
wr: cannot write to /proc/kcore
```
然后通过`Systemtap`修改是可以：
```
stap -g -e 'probe kernel.function("devmem_is_allowed").return { $return =1 }'
```
> 我在`vmware`中修改了`devmem_is_allowed`后再去打开`crash`就会直接导致`vmware`卡住，不清楚是什么原因导致的，起初以为是因为新编译的内核缺少一个`vmware`需要的模块导致的，即报错`dracut[38489]: Failed to install module libnvdimmvmxnet3`，这其实是两个模块`libnvdimm`和`vmxnet3`，可以通过修改`/etc/dracut.conf.d/nvdimm-security.conf`，把`add_drivers+="libnvdimm"`改成`add_drivers+="libnvdimm "`即可，后来我发现就算修复了这个问题还是会卡住。


# `kdump`
没办法只能去看一下内核崩溃的原因，就得保存内核崩溃时的状态，这就用到了`kdump`，这是一个基于`kexec`的内核崩溃捕获机制，可以将`kernel`崩溃前的内存镜像保存下来。原理很简单，大概就是在内核崩溃时，`kdump`启动`kexec`启动到第二个内核，也称为捕获内核，这个内核会与相应的`ramdisk`组件一个微型环境搜集`生产内核(第一内核)`的内存信息并转存。


`kdump`的实现也是需要条件的，捕获内核的启动绕过了`BIOS`由`生产内核`在崩溃时候通过`kexec`启动，这就需要`捕获内核`一开始就已经加载完成，这就是转存机制实现的关键两点：
1. `kexec_load`系统调用会在`生产内核`启动时候加载`捕获内核`到指定地址
2. 用户态下通过`kexec-tools`将`捕获内核`地址传递给`生产内核`，得以在崩溃时运行。


排查系统时候发现，`kdump`并没有被打开，且去尝试`systemctl start kdump`时候还会直接报错，报错信息简单来说就是`内存不足`，内核启动参数中有一个传入参数是`crashkernel`，这个参数用于配置`捕获内核`的大小和位置，一般会看到内核参数设置都是`crashkernel=auto`，这会根据内存自动`reserve`内存出来使用，然而如果内存在`8G`以下的话，其实并不会保留内存出来，因此对于加内存来说，我手动修改了`/boot/grub/grub.cfg`的内核参数为`crashkernel=256M`，成功开启`kdump`，从而获取到了崩溃的内核镜像。
> 不过我自己物理机排查都发现保留内存为0,那有点怀疑是可能是哪个版本的内核直接就自动关闭了这部分的保留，除非手动设置。`cat /sys/kernel/kexec_crash_size`这样查看保留了多少内存。


# `CONFIG_HARDENED_USERCOPY`
调试崩溃内核时发现错误出现在了`mm/usercopy.c:72`这个位置，当直接翻开源码观察后，发现这儿本来就会去主动发起一个`BUG()`，然后产生中断，那就说明是一个内核的`feature`，结果发现在内核`4.8`以后内核主线中引入了一个特性是`CONFIG_HARDENED_USERCOPY`，简单来说就是针对`copy_form_user()/copy_to_user()`这两个函数做安全加固，从而避免`内核内存泄露`和`内核内存覆盖`的问题出现，至于加固细节大概就是`指针检查`，`指向检查`，`拷贝大小不允许越界(slab分配对象)`，`涉及内核栈的拷贝的内容需要在当前进程内核栈中`，为了方便就直接修改了`.config`然后重编译了内核。


# `/dev/mem`
上面说过写入的操作最大的障碍就是`devmem_is_allowed`，这个函数影响是是`crash`针对`/dev/mem`的访问，`/dev/mem`可以看做是一个`内存入口`，这个入口提供了一个针对`全物理地址`访问的能力。简单来说只要能确定地址空间分布，就可以指定任意有效地址映射到用户空间中，因此`kernel`自然要对其加以限制，而最核心的检查就是`devmem_is_allowed`，简单来说如果关了这个选项用户可以获得完全读写能力。


# 参考文档
* [SystemTap使用指南](http://itranslation.cn/?p=598)
* [Linux Kernel Memory Hacking](http://oliveryang.net/2017/03/linux-kernel-memory-hacking/)
* [解决Linux内核问题实用技巧之 - Crash工具结合/dev/mem任意修改内存](https://mp.weixin.qq.com/s/QY4GNoWsely-oeIE52iEug)
* [Linux Systemtap和gdb工具实用技巧两则](https://blog.csdn.net/dog250/article/details/102843872)
* [(德语)CentOS 7 – Probleme mit VMware Tools](https://www.shakral.de/blog/2019/09/23/centos-7-probleme-mit-vmware-tools/)
* [实例使用crash分析Kdump转储kernel崩溃内核](https://xiaoyeshiyu.github.io/linux/fae/2017/05/11/%E5%AE%9E%E4%BE%8B%E4%BD%BF%E7%94%A8crash%E5%88%86%E6%9E%90Kdump%E8%BD%AC%E5%82%A8kernel%E5%B4%A9%E6%BA%83%E5%86%85%E6%A0%B8/)
* [使用 Kdump 检查 Linux 内核崩溃](https://linux.cn/article-8737-1.html)
* [Hardened usercopy](https://lwn.net/Articles/695991/)
* [Android 8.0 内核安全特性](https://geneblue.github.io/2017/08/23/Android8.0_Kernel_Hardening/)
* [/dev/mem可没那么简单](https://blog.csdn.net/skyflying2012/article/details/47611399)
* [系统崩溃 - crash工具介绍](https://www.jianshu.com/p/ad03152a0a53)