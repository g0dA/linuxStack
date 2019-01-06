# 下载
[mirrors.kernel.org](https://mirrors.edge.kernel.org/pub/linux/kernel/)
这儿可以下载到各个版本的linux内核
在`/usr/src/`下解压
```
tar xzvf linux-x.x-xx.tar.gz
```

## 准备编译环境
```
sudo apt-get install git fakeroot build-essential ncurses-dev xz-utils libssl-dev bc flex libelf-dev bison
```

编译前需要准备好`gcc`环境，在编译`2.6`内核时候因为`gcc`问题一直在报错，因此要先安装一个低版本的`gcc`
> `gcc`环境不存在降级，而是多版本并存

以`ubuntu`为例，安装`gcc-3.4`，先修改源，将如下内容添加到`/etc/apt/sources.list`中
```
deb http://snapshot.debian.org/archive/debian/20070730T000000Z/ lenny main
deb-src http://snapshot.debian.org/archive/debian/20070730T000000Z/ lenny main
deb http://snapshot.debian.org/archive/debian-security/20070730T000000Z/ lenny/updates main
deb-src http://snapshot.debian.org/archive/debian-security/20070730T000000Z/ lenny/updates main
```
执行`apt-get update`，可能会出现如下信息：
```
W: GPG error: http://snapshot.debian.org lenny/updates Release: The following signatures couldn't be verified because the public key is not available: NO_PUBKEY A70DAF536070D3A1
```
无视直接安装：
```
sudo apt-get install gcc-3.4 g++-3.4
```
这样通过`dpkg --list | grep compiler`就能看到我们已经安装好了两个`gcc`环境，然后就是修改`gcc`的命令链接
> 使用`update-alternative`可以非常方便的更换链接

安装好链接
```
sudo update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-4.8 60 --slave /usr/bin/g++ g++ /usr/bin/g++-4.8
sudo update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-3.4 40 --slave /usr/bin/g++ g++ /usr/bin/g++-3.4
```
然后选取
```
sudo update-alternatives --config gcc
```
现在`gcc -v`看一下，当前是否为`3.4`版本

# 编译
```
make mrproper
make clean
```
先执行下净化下原始源码。
接着执行
```
make menuconfig
make defconfig 
```
这儿到底该怎么配，建议看[鸟哥linux私房菜](https://doc.plob.org/vbird_linux/linux/linux_basic/0540kernel.htm)

> 往往这时候会出错，请参考[编译一个gcc 4.8](https://blog.argcv.com/articles/2946.c)和[cannot find crti.o: No such file or directory](
https://askubuntu.com/questions/251978/cannot-find-crti-o-no-such-file-or-directory)我是`libc`的问题，这儿建议一个个谷歌错误，反正问题真的多，一度想放弃

其中我用的`gcc 3.4.6`存在一个文件未能链接到正常库文件的问题
```
make   //编译
```
等待一个电影的时间，编译完成。
> 出现`unsupported instruction 'mov'`的报错，这是因为在`x64架构`的机器上编译，需要给编译器指定用`32位`，即在`Makefile`所有的`AS`指令后面加上`--32`，在所有的`CC`后面加上`-m32`，但是还是存在各种问题，没办法，更换成`gcc-4.4`，需要重新修改链接，同时我也修改了我的源码从`2.6.0`换成了`2.6.32.1`，现在`make`没啥问题

编译完成没有报错的话，安装先前启用的那些模块
```
make modules_install
```
都结束后，安装内核
```
make install
```
最后就是将安装好的内核作为引导了，如果是`grub`的话则设置后更新下`grub`
```
sudo update-initramfs -c -k 2.6.32.1
sudo update-grub
```
> 然后我就还是进入到了当前的内核里！！查看下`grub.cfg`中，发现`2.6.32.1`是写进去的，然后我是虚拟机的问题，因此要修改默认的入口，这个属于`Advanced options`，因此修改`/etc/default/grub`变成`GRUB_DEFAULT="Ubuntu, with Linux 2.6.32.1"`，然后有可能会提示`Warning: Please don't use old title `Ubuntu, with Linux 2.6.32.1'`，这样按照后面的提示修改了就行。

# 参考
* [Answers](https://askubuntu.com/questions/923337/installing-an-older-gcc-version3-4-3-on-ubuntu-14-04-currently-4-8-installed)
* [如何编译 Linux 内核](https://linux.cn/article-9665-1.html)
* [/usr/bin/ld: cannot find -lgcc_s 问题解决小记](https://www.cnblogs.com/cassvin/archive/2011/07/24/Linux_Qtopia_firstBlogOncnblogs.html)
* [64位Debian Sid下编译Linux 0.11内核](https://www.zybuluo.com/qqiseeu/note/1255)
* [Linux 内核编译](https://jin-yang.github.io/post/kernel-compile.html)
* [记一次编译linux 2.6 和4.10内核源码](https://blog.csdn.net/think_ycx/article/details/80775415)
* [修改Grub默认启动项](https://forum.ubuntu.org.cn/viewtopic.php?f=139&t=486436)