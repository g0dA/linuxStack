# 进程诞生学习小记
> 这个玩意不亚于开天辟地，因此必须要重头说起

我们只从`内核加载`开始说起，那么从实际代码上，一切的一切都是从`start_kernel()`开始的，这个代码是内核真正的初始化过程，使得一个完整的`linux内核环境`被建立起来。(而在此之前的初始化只是为了能够让内核程序最低限度的执行初始化操作)
> 只管和进程创建有关的

我的是`v4.15内核`，第一个关注到的操作就是这一行代码：
```
set_task_stack_end_magic(&init_task);
```
先看一下函数的实现，来源于`fork.c`
```
void set_task_stack_end_magic(struct task_struct *tsk)
{
 unsigned long *stackend;
 stackend = end_of_stack(tsk);
 *stackend = STACK_END_MAGIC; /* for overflow detection */
}
```
`end_of_stack`呢在`task_stack.h`里面，非常简单的一个函数，就是返回`内核栈边界地址`：
```
static inline unsigned long *end_of_stack(struct task_struct *p)
{
#ifdef CONFIG_STACK_GROWSUP
 return (unsigned long *)((unsigned long)task_thread_info(p) + THREAD_SIZE) - 1;
#else
 return (unsigned long *)(task_thread_info(p) + 1);
#endif
}
```
接着`set_task_stack_end_magic`会把`栈底地址`设置成`STACK_END_MAGIC`作为`栈溢出`的标志。
这不是什么问题，主要来看下`set_task_stack_end_magic`的传参`&init_task`，它在`init_task.c`中被初始化：
```
struct task_struct init_task = INIT_TASK(init_task);
EXPORT_SYMBOL(init_task);
```
最终就定位到了`INIT_TASK`，这可以理解成一个手动初始化出来的`进程结构`。看源码的话也能很轻易的看出是一个`task_struct`的数据结构。
至此第一个`task_struct`就现身了，也就是`init_task`，但此刻的它还只是一个`进程描述符`，还需要运行起来。
```
 /*
  * Set up the scheduler prior starting any interrupts (such as the
  * timer interrupt). Full topology setup happens at smp_init()
  * time - but meanwhile we still have a functioning scheduler.
  */
 sched_init();
```
这个函数初始化了各种调度相关的数据结构，其中有一条代码：
```
 /*
  * Make us the idle thread. Technically, schedule() should not be
  * called from this thread, however somewhere below it might be,
  * but because we are the idle thread, we just pick up running again
  * when this runqueue becomes "idle".
  */
 init_idle(current, smp_processor_id());
```
而此时的`current`就是`&init_task`，再跟入看下
```
__sched_fork(0, idle);
```
至此`init_task`被初始化成`0号进程`也就是`idle进程`进入到了`cpu运行队列`中。
> `init_task`是`idle`的进程描述符，也是整个内核第一个`进程描述符`，他是被静态创建的。

继续跟下去，就来到了`start_kernel`的结尾`rest_init();`，这个函数的统一说法是什么呢？
```
这个函数的主要使命就是创建并启动内核线程init。
```
跟进去看，跳过第一步的`RCU锁机制启动函数`：
```
 /*
  * We need to spawn init first so that it obtains pid 1, however
  * the init task will end up wanting to create kthreads, which, if
  * we schedule it before we create kthreadd, will OOPS.
  */
 pid = kernel_thread(kernel_init, NULL, CLONE_FS);
```
注释的意思是说：
```
我们必须先创建一个init线程这样它就能获得pid=1,虽然init线程会挂起来等待kthreads创建，如果我们提前调度init就会导致oops。
```
先看一下`kernel_thread`吧
```
/*
 * Create a kernel thread.
 */
pid_t kernel_thread(int (*fn)(void *), void *arg, unsigned long flags)
{
 return _do_fork(flags|CLONE_VM|CLONE_UNTRACED, (unsigned long)fn,
  (unsigned long)arg, NULL, NULL, 0);
}
```
那简单了，`pid=1`的人找到了，就是`kernel_init`。当然还没几行：
```
pid = kernel_thread(kthreadd, NULL, CLONE_FS | CLONE_FILES);
```
至此`linux`中的前三个`进程`产生了，说一说作用：
```
* idle进程由系统自动创建, 运行在内核态 
idle进程其pid=0，其前身是系统创建的第一个进程，也是唯一一个没有通过fork或者kernel_thread产生的进程。完成加载系统后，演变为进程调度、交换

* init进程由idle通过kernel_thread创建，在内核空间完成初始化后, 加载init程序, 并最终用户空间 
由0进程创建，完成系统的初始化. 是系统中所有其它用户进程的祖先进程 
Linux中的所有进程都是有init进程创建并运行的。首先Linux内核启动，然后在用户空间中启动init进程，再启动其他系统进程。在系统启动完成完成后，init将变为守护进程监视系统其他进程。

* kthreadd进程由idle通过kernel_thread创建，并始终运行在内核空间, 负责所有内核线程的调度和管理 
它的任务就是管理和调度其他内核线程kernel_thread, 会循环执行一个kthread的函数，该函数的作用就是运行kthread_create_list全局链表中维护的kthread, 当我们调用kernel_thread创建的内核线程会被加入到此链表中，因此所有的内核线程都是直接或者间接的以kthreadd为父进程 
```
* 统一来说就是，`init`是所有用户态进程的祖先，`kthreadd`是所有内核线程的祖先。

>  这儿先抛出一个知识：Linux上进程分3种，内核线程（或者叫核心进程）、用户进程、用户线程。

说完了上述的三个进程，就该说说其余进程的创建了。
Linux提供了三种创建进程的方式：
1. fork
2. vfork
3. clone

但是这三种方式归根到底都是使用的`do_fork`来实现，而核心原理也是通过复制`task`然后做处理。
但是能接触到的实际都是`用户态`进程，因此还需要继续把上述的过程往用户态引申，可以看下`ps -aux`的执行结果，`systemd`是`PID`为1的进程，而这个进程的`command`是`/sbin/init`，那这个到底是什么时候执行的呢？
* 答案是是在`kernel`加载之后，结束之前。

在`complete(&kthreadd_done);`这个操作通知了`kernel_init`已经完成了`kthreadd`的创建后，首先是`rest_init`的`schedule_preempt_disabled();`，它的注释是这样的：
```
 /*
  * The boot idle thread must execute schedule()
  * at least once to get things moving:
  */
```
就是说为了让系统跑起来，`boot idle`至少执行一次`schedule()`，执行之后`kernel_init`和`kthreadd`就也同时运行起来了。
> 这部分的运行机制需要涉及到调度系统的知识，总的来说就是全局考评，确定需要执行的进程。

`rest_init`的最后一个操作是`cpu_startup_entry(CPUHP_ONLINE);`，而这个操作是这样的：
```
void cpu_startup_entry(enum cpuhp_state state)
{
 /*
  * This #ifdef needs to die, but it's too late in the cycle to
  * make this generic (arm and sh have never invoked the canary
  * init for the non boot cpus!). Will be fixed in 3.11
  */
#ifdef CONFIG_X86
 /*
  * If we're the non-boot CPU, nothing set the stack canary up
  * for us. The boot CPU already has it initialized but no harm
  * in doing it again. This is a good place for updating it, as
  * we wont ever return from this function (so the invalid
  * canaries already on the stack wont ever trigger).
  */
 boot_init_stack_canary();
#endif
 arch_cpu_idle_prepare();
 cpuhp_online_idle(state);
 while (1)
  do_idle();
}
```
可以看到最后在无限循环一个`do_idle()`，内核会进入到`idle状态`，循环消耗空闲的`cpu时间片`，当有其他进程需要工作时候，就会被抢占，至此整个内核就运行结束了。
有个资料总结的就挺好的：
```
简单来说，linux内核最终的状态是：有事干的时候去执行有意义的工作（执行各个进程任务），实在没活干的时候就去死循环（实际上死循环也可以看成是一个任务）。
```
## kernel_init

这时候就要说到`kernel_init`了，进入到源码中，就能很轻易的看到针对`/sbin/init`的调用。
```
static int __ref kernel_init(void *unused)
{
 int ret;

 kernel_init_freeable();
 /* need to finish all async __init code before freeing the memory */
 async_synchronize_full();
 ftrace_free_init_mem();
 free_initmem();
 mark_readonly();
 system_state = SYSTEM_RUNNING;
 numa_default_policy();

 rcu_end_inkernel_boot();

 if (ramdisk_execute_command) {
  ret = run_init_process(ramdisk_execute_command);
  if (!ret)
   return 0;
  pr_err("Failed to execute %s (error %d)\n",
         ramdisk_execute_command, ret);
 }

 /*
  * We try each of these until one succeeds.
  *
  * The Bourne shell can be used instead of init if we are
  * trying to recover a really broken machine.
  */
 if (execute_command) {
  ret = run_init_process(execute_command);
  if (!ret)
   return 0;
  panic("Requested init %s failed (error %d).",
        execute_command, ret);
 }
 if (!try_to_run_init_process("/sbin/init") ||
     !try_to_run_init_process("/etc/init") ||
     !try_to_run_init_process("/bin/init") ||
     !try_to_run_init_process("/bin/sh"))
  return 0;

 panic("No working init found. Try passing init= option to kernel. "
       "See Linux Documentation/admin-guide/init.rst for guidance.");
}
```
前半部分都不太需要管，而这儿就要注意两个函数`run_init_process`和`try_to_run_init_process`，`try_to_run_init_process`是调用的`run_init_process`，而最终调用的是`do_execve`，这是来加载运行可执行程序的函数。
而从上到下可能执行的部分有：
1. `ramdisk_execute_command`
2. `execute_command`
3. `try_to_run_init_process("/sbin/init")||`
    `try_to_run_init_process("/etc/init")||`
    `try_to_run_init_process("/bin/init")||`
    `try_to_run_init_process("/bin/sh")`

第一和第二都是由`内核启动参数`来决定的，分别是`rdinit=`和`init=`：
```
static int __init init_setup(char *str)
{
 unsigned int i;

 execute_command = str;
 /*
  * In case LILO is going to boot us with default command line,
  * it prepends "auto" before the whole cmdline which makes
  * the shell think it should execute a script with such name.
  * So we ignore all arguments entered _before_ init=... [MJ]
  */
 for (i = 1; i < MAX_INIT_ARGS; i++)
  argv_init[i] = NULL;
 return 1;
}
__setup("init=", init_setup);

static int __init rdinit_setup(char *str)
{
 unsigned int i;

 ramdisk_execute_command = str;
 /* See "auto" comment in init_setup */
 for (i = 1; i < MAX_INIT_ARGS; i++)
  argv_init[i] = NULL;
 return 1;
}
__setup("rdinit=", rdinit_setup);
```
倘若都没有设置的话，就会执行到硬编码路径的执行程序，按照顺序依次如下：
```
/sbin/init
/etc/init
/bin/init
/bin/sh
```
如果什么都没有的话，就进入`kernel panic`。
那按照正常流程下，整个系统运行的第一个用户态可执行程序就是`/sbin/init`了，而因为是通过`do_execve`装载的程序，`PID`为`1`的进程的`代码段`被替换成新程序的`代码段`，而原有的`数据段`和`堆栈段`则被放弃，然后重新分配，唯一保留的就还是`PID`了，那此刻整个系统中`PID=1`的已经从`kernel_init`这个在内核态运行的`内核代码`变成了`/sbin/init`这个用户态的进程。
```
PID=1：
kernel_init => /sbin/init
```
至此，第一个用户态进程也就正式出现了，以前叫`init`，现在叫`systemd`。

## 用户态下的新进程
> 那现在看一下，用户态下一个新程序运行的话，其进程的创建过程是什么

就以`fork`来说：
```
p = copy_process(clone_flags, stack_start, stack_size,
    child_tidptr, NULL, trace, tls, NUMA_NO_NODE);
```
会拷贝一份进程信息，`内核栈`和`thread_info`与父进程相同。接着根据这个`新描述符`获取到一个`pid`，其中关于`pid`的诞生：
```
pid = alloc_pid(p->nsproxy->pid_ns_for_children);
```
`alloc_pid`为`子进程描述符`分配了对应的`描述符号`。
> 此时子进程要使用的`pid`就诞生了

接着就是从`子进程描述符`中获取`pid`
```
pid = get_task_pid(p, PIDTYPE_PID);
```
这就值得玩味了？这个`pid`到底是一个什么获取法？
`get_task_pid(struct tast_struct *task)` => `if (type != PIDTYPE_PID){task = task->group_leader;}` => `get_pid(task->pids[type].pid)` => `atomic_inc(&pid->count);`
`atomic_inc`是个`原子操作`函数，作用呢就是`原子变量值加一`，效果就是把`count+1`，再接着就是一个获取`子进程`的`nr值`的操作：
```
nr = pid_vnr(pid);
.........pid_nr_ns.........
nr = upid->nr
```
那此刻就得知道下`pid`的结构了：
```
struct pid
{
 atomic_t count;
 unsigned int level;
 /* lists of tasks that use this pid */
 struct hlist_head tasks[PIDTYPE_MAX];
 struct rcu_head rcu;
 struct upid numbers[1];
};
```
1. `count`是引用计数器
2. `level`是该进程的命名空间在命名空间层次结构中的深度
3. `numbers`是一个`upid`实例的数组，每个数组对应一个命名空间(表现上只有一个，但是可以扩展)
4. `tasks`是共享此`pid`的所有进程的链表表头，其中的进程通过`pids[type]`成员构链接。

后面就是返回`nr`值了，那也就是说，实际上最重要的部分在于`copy_process`
> 该函数会用当前进程的一个副本来创建新进程并分配pid，但不会实际启动这个新进程。它会复制寄存器中的值、所有与进程环境相关的部分，每个clone标志。新进程的实际启动由调用者来完成。

那么就是一个`do_fork`就必然会产生一个`PID`，至于用不用两说。

## `namespcae`

虚拟化的东西，很难理解，先放着吧。。。。

# 参考资料
* [Linux pid，tgid关系](https://blog.csdn.net/huyoufu200920201078/article/details/78082181)
* [为何线程有PID？](https://blog.csdn.net/lh2016rocky/article/details/55671656)
* [Linux内核 ——进程管理之进程诞生（基于版本4.x](https://www.cnblogs.com/holyxp/p/9452357.html)
* [linux pid名字空间](https://blog.csdn.net/wyg_031113/article/details/50894118)
* [Linux开机启动十步骤](https://blog.csdn.net/jmppok/article/details/53334488)
* [Linux 开机引导和启动过程详解](https://linux.cn/article-8807-1.html)
* [进程的诞生](https://blog.csdn.net/robinsongsog/article/details/82354736)
* [linux源码分析（三）－start_kernel](https://www.cnblogs.com/yjf512/p/5999532.html)
* [Linux下0号进程的前世(init_task进程)今生(idle进程)----Linux进程的管理与调度（五）](https://blog.csdn.net/gatieme/article/details/51484562)
* [Linux进程的管理与调度（六） -- Linux下1号进程的前世(kernel_init)今生(init进程)](https://blog.csdn.net/armlinuxww/article/details/78556541)
* [(转)Linux内核本身和进程的区别 内核线程、用户进程、用户线程](https://www.cnblogs.com/heluan/p/8532365.html)
* [分析Linux内核创建一个新进程的过程](https://www.cnblogs.com/Nancy5104/p/5338062.html)
* [Linux进程调度——schedule()函数分析](https://blog.csdn.net/lsl180236/article/details/51155373)
* [Linux内核源码分析--内核启动之(5)Image内核启动(rest_init函数)（Linux-3.0 ARMv7）](http://blog.chinaunix.net/uid-20543672-id-3172321.html)
* [内核启动之start_kernel()和rest_init()函数](https://msd.misuland.com/pd/2884250137616449734)
* [Linux内核同步机制之（一）：原子操作](https://www.cnblogs.com/liaokang/p/5620694.html)
* [Linux进程管理(2)：进程创建的copy_process和进程销毁](https://blog.csdn.net/zhoudaxia/article/details/7367044)