# 引言
`runc`的`create`命令可以通过指定一个`config.json`来创建出一个容器进程
```
$ sudo runc create test
$ sudo runc list
ID          PID         STATUS      BUNDLE                          CREATED                          OWNER
test        15140       created     /home/lang/Desktop/runc/build   2021-05-13T07:43:32.167623581Z   root
$ sudo lsof -p 15140 -R
COMMAND     PID PPID USER   FD      TYPE DEVICE SIZE/OFF     NODE NAME
runc:[2:I 15140  814 root  cwd       DIR  259,3     4096 11141709 /
runc:[2:I 15140  814 root  rtd       DIR  259,3     4096 11141709 /
runc:[2:I 15140  814 root  txt       REG  259,3 10396536  5283031 /
runc:[2:I 15140  814 root    0u      CHR  136,2      0t0        5 /dev/pts/2
runc:[2:I 15140  814 root    1u      CHR  136,2      0t0        5 /dev/pts/2
runc:[2:I 15140  814 root    2u      CHR  136,2      0t0        5 /dev/pts/2
runc:[2:I 15140  814 root    4w     FIFO   0,12      0t0   318203 pipe
runc:[2:I 15140  814 root    5u     FIFO   0,23      0t0     1666 /run/runc/test/exec.fifo
runc:[2:I 15140  814 root    7u  a_inode   0,13        0    12090 [eventpoll]
```
虽然此时的容器的初始进程还是保持为`runc`本身，然而已经设置好了`namespace`形成了隔离的环境，简而言之就是到此为止还是`用户无关逻辑`，所有的配置和功能全都由`runc`本身的逻辑实现，不会加载任何其余代码。


# 调用
> 只谈论一些有主要影响的逻辑


读取配置文件，其中包含了针对配置文件的合法性校验需要满足`OCI`标准，通过文本读取并最终解码为一个`specs.Spec`结构交由整个上下文中使用。
```
spec, err := setupSpec(context)
```
在`create`的逻辑里启动容器其实是一个很漫长的逻辑，而入口就是
```
status, err := startContainer(context, spec, CT_ACT_CREATE, nil)
```
如果想启动`container`那么首先就得创建一个`container`出来，这个流程依赖于`libcontainer`的实现，可以看到项目中的注解这样写道：
```
Because containers are spawned in a two step process you will need a binary that will be executed as the init process for the container. In libcontainer, we use the current binary (/proc/self/exe) to be executed as the init process, and use arg "init", we call the first step process "bootstrap", so you always need a "init" function as the entry of "bootstrap".
```
就是说首先会用自身当作是一个`factory`执行一个`init`方法
```
l := &LinuxFactory{
        Root:      root,
        InitPath:  "/proc/self/exe",
        InitArgs:  []string{os.Args[0], "init"},
        Validator: validate.New(),
        CriuPath:  "criu",
    }
```
但是到目前为止其实都还没有新的进程产生，还只是属于配置阶段直到`factory.Create(id, config)`才开始进入到基础部署的阶段，来看一下这个创建出来的`工厂`到底是个什么样子的东西。
跳过几个判断就能看到第一个重要的点，关于`containerRoot`的配置
```
containerRoot, err := securejoin.SecureJoin(l.Root, id)
```
跟入看一下这个函数的作用，实际就是针对`SecureJoinVFS`的封装，虽然注释写了很多，但是从最终结果来看实际就是生成了一个工厂路径而已，甚至连文件都没有创建。
```
containerRoot, err := securejoin.SecureJoin(l.Root, id)  err: nil  containerRoot: "/run/runc/test"
```
等到`工厂`被创建好后则开始填充`linuxContainer`结构，而这个结构在上下文中就是一个`container`。
```
    c := &linuxContainer{
        id:            id,
        root:          containerRoot,
        config:        config,
        initPath:      l.InitPath,
        initArgs:      l.InitArgs,
        criuPath:      l.CriuPath,
        newuidmapPath: l.NewuidmapPath,
        newgidmapPath: l.NewgidmapPath,
        cgroupManager: l.NewCgroupsManager(config.Cgroups, nil),
    }
```
容器归根到底就是一个进程，一个`container`能够被具象化出来那就需要被启动，而`container`又只是上下文中的一个结构而已，将其启动就需要再进行一层`runner`的封装，依照这个封装交由底层程序来决定进行能逻辑将容器最终启动起来，因此这个`runner`也可以理解为一个`操作配置`。
```
process, err := newProcess(*config, r.init, r.logLevel)
```
配置容器进程的启动信息，包括`执行参数`，`环境变量`等等，然后就是设置`信号处理`还有`tty`，最终进入到`操作选择`之中，决定如何将进程正式启动起来：
```
    switch r.action {
    case CT_ACT_CREATE:
        err = r.container.Start(process)  //Create的逻辑会落入这个当中
    case CT_ACT_RESTORE:
        err = r.container.Restore(process, r.criuOpts)
    case CT_ACT_RUN:
        err = r.container.Run(process)
    default:
        panic("Unknown action")
    }
```
设置新进程的`NS`配置，这个就是读取`config`中的ns配置然后循环填充
```
    nsMaps := make(map[configs.NamespaceType]string)
    for _, ns := range c.config.Namespaces {
        if ns.Path != "" {
            nsMaps[ns.Type] = ns.Path
        }
    }
```
接着会构建`init`进程，同时创建了一个`socketpair`用来来建立进程间的通信，而`init`进程则会读写`childInitPipe`当前进程则会读写`parentPipe`
```
cmd := c.commandTemplate(p, childInitPipe, childLogPipe)
```
启动`init`进程，此刻这个进程的`ns`还是没有被隔离的
```
err := p.cmd.Start()


  26209   26201      \_ /tmp/___runcdebug create test
 174440   26209          \_ /tmp/___runcdebug init  
```
下面就会有一个很神奇的逻辑出现，如下操作逻辑仅仅是将`p.bootstrapData`写入到`parent pipe`中
```
    if _, err := io.Copy(p.messageSockPair.parent, p.bootstrapData); err != nil {
        return newSystemErrorWithCause(err, "copying bootstrap data to pipe")
    }
```
然而此刻去观察进程的话会发现此刻的`ns`已然发生了变化，但这是什么时候的事情？？回顾到上面这个`io.copy`之中，`ns`相关的数据都是被写入到`bootstrapData`里面然后再写入管道中，那一般来说管道的另一边就应该是负责处理`ns`变化的进程，然而按照管道对端来说这个进程就是`___runcdebug`才对，然而问题就出在`Golang`这个语言上。
`namespace`的变化一般来说都需要用到`setns`这个系统调用或者在刚开始`clone`时候就设置好`flag`，然而`golang`在多数情况下是一个`go runtime`的多线程环境，而这种环境下`setns`并不能正确的运行，那么如果想要真的运行起来就需要让`setns`在多线程环境之前就生效，但是可惜的是`golang`又没有能够在程序启动前执行某段代码的机制，但是`C`却有gcc扩展` __attribute__((constructor)) `能够实现程序启动前执行代码，因此就有了`cgo`的代码引入来负责这个事情，而执行时机可以来验证一下是否确实是在`io.Copy`之后，只需要在`nsexec()`函数中加点输出就行了：
```
package nsenter


/*
#cgo CFLAGS: -Wall
extern void nsexec();
void __attribute__((constructor)) init(void) {
    nsexec();
}
*/
import "C"
```
那么就是说从这儿为止，除了通过`pipe`传输一点配置信息以外，逻辑就不再是`create`的逻辑了，后续的大部分操作都是由`init`和`nsexec`来负责，既然`nsexec`是先于`init`执行的，那就先来看一下`nsexec`的流程。
## `nsexec`
```
    pipenum = initpipe();
```
从环境变量里获取到通信管道用来读写配置和消息，接着就是已很有意思的逻辑
```
    /*
     * We need to re-exec if we are not in a cloned binary. This is necessary
     * to ensure that containers won't be able to access the host binary
     * through /proc/self/exe. See CVE-2019-5736.
     */
    if (ensure_cloned_binary() < 0)
        bail("could not ensure we are a cloned binary");
```
可以看到注释上说明代码是用来修补`CVE-2019-5736`的，这个漏洞就是当年著名的`runc exec`逃逸的漏洞，可以参考这个[commit](https://github.com/opencontainers/runc/commit/0a8e4117e7f715d5fbeef398405813ce8e88558b)，核心逻辑就是通过`memfd_create`来在内存中拷贝一个新的`runc`用来处理后续的逻辑防止逃逸。
从管道中读取`namespace`的配置填充到结构体里
```
struct nlconfig_t {
    char *data;


    /* Process settings. */
    uint32_t cloneflags;
    char *oom_score_adj;
    size_t oom_score_adj_len;


    /* User namespace settings. */
    char *uidmap;
    size_t uidmap_len;
    char *gidmap;
    size_t gidmap_len;
    char *namespaces;
    size_t namespaces_len;
    uint8_t is_setgroup;


    /* Rootless container settings. */
    uint8_t is_rootless_euid;    /* boolean */
    char *uidmappath;
    size_t uidmappath_len;
    char *gidmappath;
    size_t gidmappath_len;
};


    /* Parse all of the netlink configuration. */
    nl_parse(pipenum, &config);
```
到此之后`nsexec`主要在于三个进程之间的设置与配置
```
 129578  129570      \_ /tmp/___runcdebug create test
 129638  129578          \_ [runc:[0:PARENT]] <defunct>
 129747  129578          \_ [runc:[1:CHILD]] <defunct>
 129748  129578          \_ /tmp/___runcdebug init
```
其中`[runc:[0:PARENT]] <defunct>`在没进入到`nsexec`之前是` \_ /tmp/___runcdebug init`创建的进程，而`129748`这个进程则是新的` \_ /tmp/___runcdebug init`。那就一个进程一个进程来看逻辑，首先先说`PARENT`进程，这个进程其实就是`p.cmd.Start()`启动的进程，上面的逻辑都是由这个进程执行，直到进入到一个`switch`当中通过三个变量来确认当前进程的逻辑，而当前进程的逻辑如下：
```
prctl(PR_SET_NAME, (unsigned long)"runc:[0:PARENT]", 0, 0, 0); // 首先是设置了进程名
stage1_pid = clone_parent(&env, STAGE_CHILD);  // 然后复制了一个完全一致的子进程
while (!stage1_complete) { // 进入到一个循环监听子进程状态的逻辑中
    ......
}
```
可以看到`PARENT`进程在当前为止都是不断的关注着新建的子进程，而在循环逻辑中还为子进程设置了`user map`，这是因为当子进程修改了`ns`后就将失去此能力，所以需要提前设置好，注意如下一点：
```
case SYNC_RECVPID_PLS:
                    write_log(DEBUG, "stage-1 requested pid to be forwarded");


                    /* Get the stage-2 pid. */
                    if (read(syncfd, &stage2_pid, sizeof(stage2_pid)) != sizeof(stage2_pid)) {
                        sane_kill(stage1_pid, SIGKILL);
                        sane_kill(stage2_pid, SIGKILL);
                        bail("failed to sync with stage-1: read(stage2_pid)");
                    }
```
这一段逻辑是`PARENT`进程用来接收到孙进程的信息，先放着以后在用继续看下去就是针对子进程结束的处理
```
                case SYNC_CHILD_FINISH:
                    write_log(DEBUG, "stage-1 complete");
                    stage1_complete = true;
                    break;
```
倘若子进程退出了则跳出当前的死循环继续流程，然后接下来却是一个针对孙进程的死循环逻辑，也就是说父进程是先监听了子进程，等子进程退出后则监听孙进程，直到都退出后自己才退出。
接下来看`CHILD`进程的逻辑，和父进程十分类似：
```
prctl(PR_SET_NAME, (unsigned long)"runc:[1:CHILD]", 0, 0, 0); // 一样的设置进程名
if (config.namespaces)  // 如果有ns设置的话，则执行下函数
            join_namespaces(config.namespaces);
```
那必然是有`ns`设置的，跟入其中后可以发现实际上就是调用`setns`来加入到现有的`ns`当中
```
    for (i = 0; i < num; i++) {
        struct namespace_t *ns = &namespaces[i];
        int flag = nsflag(ns->type);


        write_log(DEBUG, "setns(%#x) into %s namespace (with path %s)", flag, ns->type, ns->path);
        if (setns(ns->fd, flag) < 0)
            bail("failed to setns into %s namespace", ns->type);


        close(ns->fd);
    }
```
但是问题就来了，现在命名都还没有新的`ns`出来啊，那使用了`setns`又有什么用呢？亮点就来了，就是如下的注释和代码：
```
            /*
             * Unshare all of the namespaces. Now, it should be noted that this
             * ordering might break in the future (especially with rootless
             * containers). But for now, it's not possible to split this into
             * CLONE_NEWUSER + [the rest] because of some RHEL SELinux issues.
             *
             * Note that we don't merge this with clone() because there were
             * some old kernel versions where clone(CLONE_PARENT | CLONE_NEWPID)
             * was broken, so we'll just do it the long way anyway.
             */
            write_log(DEBUG, "unshare remaining namespace (except cgroupns)");
            if (unshare(config.cloneflags & ~CLONE_NEWCGROUP) < 0)
                bail("failed to unshare remaining namespaces (except cgroupns)");
```
调用了`unshare`来隔离了其余的`ns`，可以看一下`man`上关于`unshare`的定义
```
NAME
       unshare - run program in new namespaces
SYNOPSIS
       unshare [options] [program [arguments]]
DESCRIPTION
       The unshare command creates new namespaces (as specified by the command-line options described below) and then executes the specified program.  If program is not given, then ``${SHELL}'' is run (default: /bin/sh).
       By  default,  a  new  namespace  persists only as long as it has member processes.  A new namespace can be made persistent even when it has no member processes by bind mounting /proc/pid/ns/type files to a filesystem path.  A namespace that has been made persistent in this way can subsequently be entered with nsenter(1) even after the program terminates (except PID namespaces where a permanently running init process is required).  Once  a  persistent namespace is no longer needed, it can be unpersisted by using umount(8) to remove the bind mount.  See the EXAMPLES section for more details.
```
设置好`namespace`后又是调用了`clone`创建了新的进程
```
            stage2_pid = clone_parent(&env, STAGE_INIT);
```
然后获取到孙进程`pid`传给父进程，等父进程传回`ack`再返回一个`ready`信号后则主动退出。
```
            s = SYNC_RECVPID_PLS;
            if (write(syncfd, &s, sizeof(s)) != sizeof(s)) {
                sane_kill(stage2_pid, SIGKILL);
                bail("failed to sync with parent: write(SYNC_RECVPID_PLS)");
            }
            if (write(syncfd, &stage2_pid, sizeof(stage2_pid)) != sizeof(stage2_pid)) {
                sane_kill(stage2_pid, SIGKILL);
                bail("failed to sync with parent: write(stage2_pid)");
            }


            /* ... wait for parent to get the pid ... */
            if (read(syncfd, &s, sizeof(s)) != sizeof(s)) {
                sane_kill(stage2_pid, SIGKILL);
                bail("failed to sync with parent: read(SYNC_RECVPID_ACK)");
            }
            if (s != SYNC_RECVPID_ACK) {
                sane_kill(stage2_pid, SIGKILL);
                bail("failed to sync with parent: SYNC_RECVPID_ACK: got %u", s);
            }


            write_log(DEBUG, "signal completion to stage-0");
            s = SYNC_CHILD_FINISH;
            if (write(syncfd, &s, sizeof(s)) != sizeof(s)) {
                sane_kill(stage2_pid, SIGKILL);
                bail("failed to sync with parent: write(SYNC_CHILD_FINISH)");
            }


            /* Our work is done. [Stage 2: STAGE_INIT] is doing the rest of the work. */
            write_log(DEBUG, "<~ nsexec stage-1");
            exit(0);
```
此时的孙进程也就是`INIT`进程已经创建起来了，那就来看一下最终的`INIT`进程的逻辑如何吧。
```
            /* We're in a child and thus need to tell the parent if we die. */
            syncfd = sync_grandchild_pipe[0];
            close(sync_grandchild_pipe[1]);
            close(sync_child_pipe[0]);
            close(sync_child_pipe[1]);


            /* For debugging. */
            prctl(PR_SET_NAME, (unsigned long)"runc:[2:INIT]", 0, 0, 0);
```
不出意料又是一个进程名的设置，提前也获取到了和父进程通信的管道，然后等着从管道中读取信息。
```
    if (read(syncfd, &s, sizeof(s)) != sizeof(s))
                bail("failed to sync with parent: read(SYNC_GRANDCHILD)");
```
后面就没什么太多的操作了，就是一些关于`sid`，`gid`的设置然后就是告诉父进程配置都准备完成，之后就是返回进入到`golang`代码的执行。
```
            s = SYNC_CHILD_FINISH;
            if (write(syncfd, &s, sizeof(s)) != sizeof(s))
                bail("failed to sync with patent: write(SYNC_CHILD_FINISH)");
```
这儿就回到了先前的部分，就是当`PARENT`进程监听到了`INIT`进程的信息后做了什么操作呢？
```
            while (!stage2_complete) {
                enum sync_t s;


                write_log(DEBUG, "signalling stage-2 to run");
                s = SYNC_GRANDCHILD;
                if (write(syncfd, &s, sizeof(s)) != sizeof(s)) {
                    sane_kill(stage2_pid, SIGKILL);
                    bail("failed to sync with child: write(SYNC_GRANDCHILD)");
                }


                if (read(syncfd, &s, sizeof(s)) != sizeof(s))
                    bail("failed to sync with child: next state");


                switch (s) {
                case SYNC_CHILD_FINISH:
                    write_log(DEBUG, "stage-2 complete");
                    stage2_complete = true;
                    break;
                default:
                    bail("unexpected sync value: %u", s);
                }
            }
```
也没啥干的，当接收到`SYNC_CHILD_FINISH`后就`break`了然后就退出了，至此为止整个`nsexec.c`的逻辑就执行完成了。


## `Init`
> 这是新进程的逻辑，我不清楚该怎么用goland的动态跟踪，因此只能直接看源码了


新进程执行了`init`的命令，因此需要跟入其中可以看到核心代码如下：
```
    Action: func(context *cli.Context) error {
        factory, _ := libcontainer.New("")
        if err := factory.StartInitialization(); err != nil {
            // as the error is sent back to the parent there is no need to log
            // or write it to stderr because the parent process will handle this
            os.Exit(1)
        }
        panic("libcontainer: container init failed to exec")
    },
```
主要就是` factory.StartInitialization();`跟入其中主要是从先前设置的环境变量里获取到管道，然后再从管道中获取到配置信息，最终进入到`Init()`中
```
i, err := newContainerInit(it, pipe, consoleSocket, fifofd, logPipeFd)
return i.Init()   //  libcontainer/standard_init_linux.go
```
这个函数中包含了各种基础环境的设置，诸如网络，主机名，rootfs，capability等配置初始化。
之后向管道中写入数据阻塞当前进程，直到管道的另一端启动`start`读出数据
```
    // Wait for the FIFO to be opened on the other side before exec-ing the
    // user process. We open it through /proc/self/fd/$fd, because the fd that
    // was given to us was an O_PATH fd to the fifo itself. Linux allows us to
    // re-open an O_PATH fd through /proc.
    fd, err := unix.Open("/proc/self/fd/"+strconv.Itoa(l.fifoFd), unix.O_WRONLY|unix.O_CLOEXEC, 0)
    if err != nil {
        return newSystemErrorWithCause(err, "open exec fifo")
    }
    if _, err := unix.Write(fd, []byte("0")); err != nil {
        return newSystemErrorWithCause(err, "write 0 exec fifo")
    }
```
最后则是利用`exec`执行容器内应该执行的命令
```
    if err := unix.Exec(name, l.config.Args[0:], os.Environ()); err != nil {
        return newSystemErrorWithCause(err, "exec user process")
    }
    return nil
```
# 参考文档
* [Go 实现容器技术的一个硬伤](https://zhuanlan.zhihu.com/p/23456448)
* [__attribute__((constructor))用法解析](https://zhuanlan.zhihu.com/p/188655590)
* [docker系列--runC解读](https://segmentfault.com/a/1190000016366810)
* [RunC 源码通读指南之 NameSpace](https://www.jianshu.com/p/a73f984f53b5)
* [runc源码分析(二)-namespace设置流程-v1-0-0-rc2](https://fankangbest.github.io/2018/01/01/runc源码分析(二)-namespace设置流程-v1-0-0-rc2/)










