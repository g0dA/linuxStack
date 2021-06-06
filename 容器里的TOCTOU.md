# 引言
群里面闲聊的时候忽然朋友给了一个漏洞过来[CVE-2021-30465](https://github.com/opencontainers/runc/security/advisories/GHSA-c3xm-pvg7-gh7r)，大致阐述的是一个出现在`runc`中的部署`rootfs`时候出现的漏洞，主要原因是针对`symlink`缺乏校验导致的绕过而产生文件系统的逃逸，那就针对这个漏洞来说道说道。


# 容器文件系统的部署
```
// standard_init_linux.go
    if err := prepareRootfs(l.pipe, l.config); err != nil {
        return err
    }
    // Set up the console. This has to be done *before* we finalize the rootfs,
    // but *after* we've given the user the chance to set up all of the mounts
    // they wanted.
    if l.config.CreateConsole {
        if err := setupConsole(l.consoleSocket, l.config, true); err != nil {
            return err
        }
        if err := system.Setctty(); err != nil {
            return errors.Wrap(err, "setctty")
        }
    }


    // Finish the rootfs setup.
    if l.config.Config.Namespaces.Contains(configs.NEWNS) {
        if err := finalizeRootfs(l.config.Config); err != nil {
            return err
        }
    }
```
中间的关于`console`的部分可以跳过，那么实际上关于`rootfs`的配置的话仅有如下两个函数而已：
1. `prepareRootfs`
2. `finalizeRootfs`


## `prepareRootfs`
> 首先明确的一点是，那就是在执行到这个逻辑的时候，新进程的`namespace`其实是已经设置完成的，但是此时的`/`挂载还是继承过来的，因此直接作变动的话会直接影响到真实环境


这个函数的逻辑其实可以分为两部分，第一部分是针对`rootfs`的配置，其中包含了`mount`和`dev`的创建等，而第二部分则是迁移，指的是`chdir`或者是`pivotRoot`这些进行目录切换和挂载切换的操作。先分析一下`rootfs`的部分，分为如下三个部分：
1. 准备基础的`rootfs`
2. 循环挂载指定的目录
3. 配置`dev`


准备基础的`rootfs`全靠`prepareRoot`一个函数就搞定了，跟进去看一下
```
func prepareRoot(config *configs.Config) error {


    flag := unix.MS_SLAVE | unix.MS_REC
    if config.RootPropagation != 0 {
        flag = config.RootPropagation
    }


    if err := unix.Mount("", "/", "", uintptr(flag), ""); err != nil { 
        return err
    }
    fmt.Printf("stop 1 minute after mount /\n")
    time.Sleep(time.Minute * 1)


    // Make parent mount private to make sure following bind mount does
    // not propagate in other namespaces. Also it will help with kernel
    // check pass in pivot_root. (IS_SHARED(new_mnt->mnt_parent))
    if err := rootfsParentMountPrivate(config.Rootfs); err != nil {
        return err
    }


    return unix.Mount(config.Rootfs, config.Rootfs, "bind", unix.MS_BIND|unix.MS_REC, "")
}
```
整个函数的主要目的就是将`rootfs`变成一个挂载点提供给后续逻辑使用，不过其中的细节还是值得一看的。首先就是一个`flag := unix.MS_SLAVE | unix.MS_REC`然后针对`/`的重挂载，这个操作是为了避免后续的挂载配置影响到外部环境，而其依赖的技术则是`Shared subtrees`，通过`slave`的挂载使得挂载信息在同一个`peer group`中单向传播。
```
    // Make parent mount private to make sure following bind mount does
    // not propagate in other namespaces. Also it will help with kernel
    // check pass in pivot_root. (IS_SHARED(new_mnt->mnt_parent))
    if err := rootfsParentMountPrivate(config.Rootfs); err != nil {
        return err
    }
```
`rootfsParentMountPrivate`这个函数主要是为了确保`rootfs`的父级挂载的`propagation type`，将其设置成`MS_PRIVATE`模式即可以挂载信息私有化，这样的话在挂载`rootfs`的时候就不会在父级挂载中传播开来。
> 挂载属性仅受父挂载影响，和祖父的`propagation type`没有关系。


当`rootfs`目录的上级挂载都配置完成后则将`rootfs`挂载起来形成一个挂载点以供后续使用。
来看这一段循环的逻辑：
```
    for _, m := range config.Mounts {
        for _, precmd := range m.PremountCmds {
            if err := mountCmd(precmd); err != nil {
                return newSystemErrorWithCause(err, "running premount command")
            }
        }
        if err := mountToRootfs(m, config.Rootfs, config.MountLabel, hasCgroupns); err != nil {
            return newSystemErrorWithCausef(err, "mounting %q to rootfs at %q", m.Source, m.Destination)
        }


        for _, postcmd := range m.PostmountCmds {
            if err := mountCmd(postcmd); err != nil {
                return newSystemErrorWithCause(err, "running postmount command")
            }
        }
    }
```
这个在配置中的表现就是容器中需要挂载的宿主机的真实目录，不过一三两个逻辑其实不用看，着重关注的只有`mountToRootfs`的实现，其作用就是把指定的目录挂载到`rootfs`的目录路径下，流程比较长，其中有个`switch`的选择这个是根据挂载的`deviceType`来决定的走不同的挂载逻辑，挑选一个容器中常用的类型来说
```
    case "bind":
        if err := prepareBindMount(m, rootfs); err != nil {
            return err
        }
        if err := mountPropagate(m, rootfs, mountLabel); err != nil {
            return err
        }
        // bind mount won't change mount options, we need remount to make mount options effective.
        // first check that we have non-default options required before attempting a remount
        if m.Flags&^(unix.MS_REC|unix.MS_REMOUNT|unix.MS_BIND) != 0 {
            // only remount if unique mount options are set
            if err := remount(m, rootfs); err != nil {
                return err
            }
        }


        if m.Relabel != "" {
            if err := label.Validate(m.Relabel); err != nil {
                return err
            }
            shared := label.IsShared(m.Relabel)
            if err := label.Relabel(m.Source, mountLabel, shared); err != nil {
                return err
            }
        }
```
这个逻辑是容器化中最常用到的逻辑并且外部可控，因为在使用容器发布的时候挂载宿主机上的一个目录当作是永久存储或者是配置挂载是一个非常常规的用途，而这个用途的底层实现就是通过`bind`的方式来挂载，`prepareBindMount`函数如同`prepareroot`一样在调用前就先预先配置好相应的目录，而到`mountPropagate`的时候就是具体的挂载操作了。
```
func prepareBindMount(m *configs.Mount, rootfs string) error {
    stat, err := os.Stat(m.Source)
    if err != nil {
        // error out if the source of a bind mount does not exist as we will be
        // unable to bind anything to it.
        return err
    }
    // ensure that the destination of the bind mount is resolved of symlinks at mount time because
    // any previous mounts can invalidate the next mount's destination.
    // this can happen when a user specifies mounts within other mounts to cause breakouts or other
    // evil stuff to try to escape the container's rootfs.
    var dest string
    if dest, err = securejoin.SecureJoin(rootfs, m.Destination); err != nil {
        return err
    }
    if err := checkProcMount(rootfs, dest, m.Source); err != nil {
        return err
    }
    // update the mount with the correct dest after symlinks are resolved.
    m.Destination = dest
    if err := createIfNotExists(dest, stat.IsDir()); err != nil {
        return err
    }


    return nil
}
```
可以看到这个函数中其实是考虑到了多种安全问题，甚至是如果回到主函数`mountToRootfs`的时候还能在`proc`类型挂载的注释上看到关于`symlink attack`的防御措施
```
        // If the destination already exists and is not a directory, we bail
        // out This is to avoid mounting through a symlink or similar -- which
        // has been a "fun" attack scenario in the past.
        // TODO: This won't be necessary once we switch to libpathrs and we can
        //       stop all of these symlink-exchange attacks.
        if fi, err := os.Lstat(dest); err != nil {
            if !os.IsNotExist(err) {
                return err
            }
        } else if fi.Mode()&os.ModeDir == 0 {
            return fmt.Errorf("filesystem %q must be mounted on ordinary directory", m.Device)
        }
```
言归正传重回到`bind`的`prepare`逻辑中，针对`source`的检测只是简单的检测了一下是否存在以防真正挂载的时候无法挂载任何东西，然后就是针对`dest`的着重检测
```
    var dest string
    if dest, err = securejoin.SecureJoin(rootfs, m.Destination); err != nil {
        return err
    }
```
这个函数的大致作用就是解决`symlink`的问题，将一个`symlink`转成`rootfs`内部的链接到的目录，意思就是说最终输出出来的路径一定是在`rootfs`以内即时是没有，举个栗子就能理解：
```
$ pwd
/home/lang/Desktop/runc/build/ubuntu
$ ls -l demotest2
lrwxrwxrwx 1 root root 6  6月  3 20:47 demotest2 -> /data/
$ ls -l data
ls: 无法访问 'data': 没有那个文件或目录
```
如果把/home/lang/Desktop/runc/build/ubuntu当作是rootfs的话，那么其中的demotest2就是链接到rootfs以外的目录，写一个测试用的代码看一下输出
```
func main() {
    root := "/home/lang/Desktop/runc/build/ubuntu"
    path := "/demotest2"
    dest, err := securejoin.SecureJoin(root, path)
    if err != nil {
    }
    fmt.Printf(dest)
}
```
输出结果如下
```
/home/lang/Desktop/runc/build/ubuntu/data
```
这个函数的作用就是如果挂载地址是一个`symlink`的话就先转换成`rootfs`中的绝对地址，即使链接目标在`rootfs`以外也会被限制住以免发生挂载逃逸的问题，当然如果真的没有这个目录的话，会主动创建出来。
```
    // update the mount with the correct dest after symlinks are resolved.
    m.Destination = dest
    if err := createIfNotExists(dest, stat.IsDir()); err != nil {
        return err
    }
```
已经设置好了`mount`的`source`和`target`那么接着就是进入到挂载的环节当中`if err := mountPropagate(m, rootfs, mountLabel);`然而其中的核心逻辑只有一行：
```
    if err := unix.Mount(m.Source, dest, m.Device, uintptr(flags), data); err != nil {
        return err
    }
```
那么意思就是说，到此为止容器上因为需求指定的需要挂载的内容就已经全部挂载好了，而后进入到`finalizeRootfs`应该说是加固的一个环节。
## `finalizeRootfs`
没什么可说的，基本就是一个加固的环节，主要是针对`/dev`下的目录还有因为`config`配置的目录设置只读。
```
// finalizeRootfs sets anything to ro if necessary. You must call
// prepareRootfs first.
func finalizeRootfs(config *configs.Config) (err error) {
    // remount dev as ro if specified
    for _, m := range config.Mounts {
        if libcontainerUtils.CleanPath(m.Destination) == "/dev" {
            if m.Flags&unix.MS_RDONLY == unix.MS_RDONLY {
                if err := remountReadonly(m); err != nil {  //重挂载
                    return newSystemErrorWithCausef(err, "remounting %q as readonly", m.Destination)
                }
            }
            break
        }
    }


    // set rootfs ( / ) as readonly
    if config.Readonlyfs {
        if err := setReadonly(); err != nil {
            return newSystemErrorWithCause(err, "setting rootfs as readonly")
        }
    }


    if config.Umask != nil {
        unix.Umask(int(*config.Umask))
    } else {
        unix.Umask(0022)
    }
    return nil
}
```
# `TOCTOU`
本质上就是一个竞争漏洞，`wiki`有个非常明显的例子：
```
Victim 
if (access("file", W_OK) != 0) {
    exit(1);
}
fd = open("file", O_WRONLY);
// Actually writing over /etc/passwd
write(fd, buffer, sizeof(buffer));


  Attacker
// After the access check
symlink("/etc/passwd", "file");
// Before the open, "file" points to the password database
```
因为正常的使用流程是先检查再打开，那么可以通过竞争在检查以后修改要打开的文件导致目标可控。回到`runc`的流程中可以明显的看出来，目录的挂载是采用了一个循环函数，先找出真实路径，然后等到下一个函数中再真正挂载，那么就可以在这个流程之间进行恶意的替换。
> 吐槽一句，这个漏洞不仅利用条件苛刻而且还没啥用，从修补的方式就可以看出来，主要是针对了`mount`的`dest`作校验


# 参考文档
* [docker-bug-allows-root-access-to-host-file-system](https://duo.com/decipher/docker-bug-allows-root-access-to-host-file-system)
* [TOCTTOU Vulnerabilities in UNIX-Style File Systems: An Anatomical Study ](https://webpages.uncc.edu/jwei8/Jinpeng_Homepage_files/toctou-fast05.pdf)
* [关于TOCTTOU攻击的简介](https://www.cnblogs.com/liqiuhao/p/9450093.html)
* [Time-of-check to time-of-use](https://en.wikipedia.org/wiki/Time-of-check_to_time-of-use)
* [mount destinations can be swapped via symlink-exchange to cause mounts outside the rootfs](https://github.com/opencontainers/runc/security/advisories/GHSA-c3xm-pvg7-gh7r)
* [rootfs: add mount destination validation](https://github.com/opencontainers/runc/commit/0ca91f44f1664da834bc61115a849b56d22f595f)
* [挂载（mount）深入理解](https://www.cnblogs.com/chen-farsight/p/6119404.html)
* [How to use/test pivot_root?](https://unix.stackexchange.com/questions/155785/how-to-use-test-pivot-root)
* [Linux中chroot与pivot_root的区别](https://blog.csdn.net/linuxchyu/article/details/21109335)
* [Pod疑难杂症（3）：Device or resource busy](https://cloud.tencent.com/developer/article/1821869)