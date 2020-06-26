> 真是好久没写到`kernel`相关的东西，先前把内存和程序相关的东西搞一搞转眼就到五月中旬了，也终于有功夫开始研究起`kernel`安全相关的东西。


关于权限就不得不先说一下`进程/线程`，对于`linux`来说其实没有什么`线程/进程`，而是只有`task`的概念，具体表现出来就是一个个的`task_struct`，但是由于`用户态`和`内核态`的特权级的问题，而出现了`内核进程`和`用户进程`的区别，然而`内核进程`的说法又是有问题的，因为先前说了对于系统来说实际只有`task`的概念，每个`task`之间应该相互独立各自有各自的资源，内核中的`task`都是公用的一份内核资源，而共享资源却又做着不同的事情是`线程`的概念，因此划分出了：
1. `内核线程`
2. `用户进程`
3. `用户线程`


> 进程是最小的资源分配单位，而线程则是最小的调度单位


回来说权限问题，`kernel`是怎么做权限管理的呢？这儿要搞明白的一件事就是`权限管理`是`kernel`提供的一个能力，它本身的运行不需要什么权限划分，可以理解成`kernel`的任意行为都是最高权限行为，而对于使用系统的人来说，才需要划分出权限来，这就有了`用户`的概念，而用户操作的本质其实就是进程访问资源，那么权限管理的实现其实主要依赖的就是两部分：
1. `用户权限划分`
2. `进程信任凭证`


`多用户`是`Unix like`的一个特性，这源于计算机设计之初的场景需要，因为以前的计算机非常的大，一个计算系统是由中央计算机和各地的终端组成的，那就必须得有一种防止不同用户相互影响的方案提出来。而渐渐的，又出现了需要协同创作修改等需求，这就出现了用户组，用户权限这些概念，而这些用户中最为特殊的莫过于`superuser`也就是`root`。
> `root`这个名字推测可能源于目录结构中的`/`


但这些其实都是设计上的概念，那么具体落实到代码和方案上是怎么实现的？这又要谈及`linux`的权限校验机制，依靠的是`uid`和`gid`，`uid`类似于身份证一样的概念，整个系统中唯一，一个用户都有一个自己的`uid`，同样的道理一个用户组也有一个`gid`，但是不同的用户可以有相同的`gid`。


用户的`uid`和`gid`是怎么对启动的进程产生影响，这才是最值得研究的一个点，一个进程的全部信息都保存在`task_struct`中，其中自然就有关于权限方面的数据，也就是`进程信任凭证`
```
 /* Process credentials: */


 /* Tracer's credentials at attach: */
 const struct cred __rcu *ptracer_cred;


 /* Objective and real subjective task credentials (COW): */
 const struct cred __rcu *real_cred;


 /* Effective (overridable) subjective task credentials (COW): */
 const struct cred __rcu *cred;
```
都是相同的结构体`task cred`，其结构如下：
```
struct cred {
    atomic_t usage;
    kuid_t uid;
    kgid_t gid;
    kuid_t suid;
    kgid_t sgid;
    kuid_t euid;
    kgid_t egid;
    kuid_t fsuid;
    kgid_t fsgid;
    unsigned int securebits;
    kernel_cap_t cap_inheritable;
    kernel_cap_t cap_permitted;
    kernel_cap_t cap_effective;
    kernel_cap_t cap_bset;
    kernel_cap_t cap_ambient;
    unsigned char jit_keyring;
    struct key *session_keyring;
    struct key *process_keyring;
    struct key *thread_keyring;
    struct key *request_key_auth;
    void *security;
    struct user_struct *user;
    struct user_namespace *user_ns;
    struct group_info *group_info;
    struct callback_head rcu;
}
SIZE: 168
```
是不是看起来有点不能理解，因为按照之前的设计理念，一个进程只需要一个`cred`且这个`cred`里面只需要保存`uid`和`gid`信息，这样就能限定该`task_struct`的权限了吗？因为资源的校验也仅仅只是看这两个值的啊？
如果光从鉴权的角度来说，这么设计是没错，但是却忽略了权限变化的事情。比如`suid`权限的执行文件，执行人的权限和实际进程的需要的权限其实并不一致，或者说进程的逻辑中存在`setuid`这样的情况，因此实际上来说，凭证中包含的信息要更为复杂以便应对不同的需求。


其实按照名称来说也就是四种：
1. `uid`和`gid` -> `real user ID`和`real group ID`
2. `suid`和`sgid` -> `saved set user ID`和`saved set group ID`
3. `euid`和`egid` -> `effective user ID`和`effective group ID`
4. `fsuid`和`fsgid` -> `file-system user ID`和`file-system group ID`


`uid`和`gid`标识了进程的真实归属，对于用户操作而产生的进程来说，其实往往都继承自初始的`shell`进程，而`shell`进程的`ID`又是在登录之初经过校验后`login`进程调用`setuid`根据用户信息设置的。先说下`euid`和`egid`，这个是校验机制中真正会去验证的`ID`，而`suid`则是一个`buffer`，是`effectice user id`的拷贝，这个`ID`的意义在于一个进程在运行过程中可以权限自由在`euid`和`uid`之间切换，因为`一个进程应该尽可能以低权限运行`，所以只有在需要时，进程才会切换到高权限。`fsuid/fsgid`比较特殊，可以算是`linux`独有的，传统`unix`中进程访问文件，发送信号，IPC通信什么的都是只依靠`euid`，然而到了`linux`中把访问文件这一个校验给分开来，单独设计了一个`fsuid/fsgid`，但是又为了和传统一致，这个值的设置依赖`euid/egid`，当`euid/egid`被修改时`fsuid/fsgid`会跟着被修改，这就保证了一致性，而唯一的区别在于可以通过`setfsuid()/setfsgid()`单独设置这个值，不过这个值现在基本没啥用了，但是为了保证软件兼容而保留下来这个值。
> 因为我通过修改一个`root`权限的`fsuid`和修改一个非`root`的`fsuid`都没能对读取`/etc/shadow`这个操作造成任何影响。参考这个`id`引入的历史原因是为了解决`NFS`，但是后来又被其余方式替代了，大概是真的没什么用了吧


回看`task_struct`中的三个凭证，其中`real_cred`和`cred`又是一个新的概念--`主客体`，其中`cred`是`主体凭证`而`real_cred`则是`客体凭证`，在正常的进程逻辑中，其实往往需要的仅仅只有`cred`用来获取资源，而倘若是遇到了进程通信这种情况时，那么一个进程是主体，一个进程是客体，被访问者就需要出示`real_cred`用来验证对方的权限。`ptracer_cred`是在`ptrace`时候才会涉及的东西，也就是`tracee`执行`exec`加载`setuid executable`的时候用到的凭证。这个设计的原因很简单：
* `tracer`可以任意更改`tracee`的`寄存器`和`内存`，而`setuid exectuable`在执行的时候会将`euid`修改成创建者的`uid`，一般情况下都是`root`，那如果不加验证的话，完全可以造成越权操作。


因此`tracee`应当保存`tracer`的`cred`，执行时验证权限，如不满足则不修改`euid`而是以原有权限执行。


# 正常的权限提升
程序的权限变化无非两个地方：
1. 启动时
2. 运行时


## 启动时的权限变化
启动时的权限变化那就要先看默认的情况下是怎么样的，先前分析过一个程序的启动流程，整个程序的加载到运行经过的有`do_execveat_common` -> `exec_binprm` -> `load_elf_binary`，一步一步地看一下关于`cred`的变化过程。


### `do_execveat_common`
这一个过程中存在一个`bprm->cred`的初始化操作`retval = prepare_bprm_creds(bprm);`，排除加锁的操作，函数调用链很简单
```
prepare_bprm_creds
    -> prepare_exec_creds

        -> prepare_creds
```
简单贴一下`prepare_creds`的逻辑
```
struct task_struct *task = current;
 const struct cred *old;
 struct cred *new;
new = kmem_cache_alloc(cred_jar, GFP_KERNEL);
old = task->cred;
 memcpy(new, old, sizeof(struct cred));
```
那么实际上来说，这儿`prepare`出来的`cred`实际上就只是其父进程的一个`copy`而已，唯一的区别就是增加了引用计数而已。接下来会有一个必要的安全检查`check_unsafe_exec`，例如是否被`ptrace`，不过并不怎么涉及权限设置，而是根据检查结果设置了几个标志位。
```
retval = prepare_binprm(bprm);
```
这一个函数调用是一个比较重点的地方，先前的文章里这儿没有细说，只是单纯的提到了调用`bprm_fill_uid`设置了权限信息，又调用`kernel_read`把`file`内容读入缓存，那这次就说道说道具体的权限变化。
```
int prepare_binprm(struct linux_binprm *bprm)
{
 int retval;
 loff_t pos = 0;
 bprm_fill_uid(bprm);
 /* fill in binprm security blob */
 retval = security_bprm_set_creds(bprm);
 if (retval)
  return retval;
 bprm->called_set_creds = 1;
 memset(bprm->buf, 0, BINPRM_BUF_SIZE);
 return kernel_read(bprm->file, bprm->buf, BINPRM_BUF_SIZE, &pos);
}
EXPORT_SYMBOL(prepare_binprm)
```
自`memset`开始就可以不理会了，只有之前的是权限相关的设置逻辑。
`bprm_fill_uid`是针对新进程`cred`的初次填充，会首先无条件的把新进程的`euid/egid`设置为当前进程的`euid/egid`
```
 bprm->cred->euid = current_euid();
 bprm->cred->egid = current_egid();
```
> `bprm->cred`是直接拷贝自`current->cred`的，但是要重新设置一遍的原因我个人觉得应该是受到`bprm_mm_init`的影响。不过影响不大，毕竟重新设置是必须经过的步骤，无法越过，但是从设计上来讲的话，应该是因为`prepare_bprm_cred`实际的作用仅仅是创建出`cred`对象出来，而`prepare_bprm`才是真正的初始化凭证信息


虽然先无条件设置了`euid/egid`，但是接着就要去检查一下`S_ISUID/S_ISGID`，说白点就是看要执行的这个程序是否被设置了`suid/sgid`，如果被设置的话，就要根据设置的内容再去修改`euid/egid`为`文件所有者/文件所有组`的ID。


`bprm_fill_uid`填充完成后就进入到了`security_bprm_set_creds`，这个是一个安全检测，但其实也存在修改`cred`的可能，这个函数调用了`LSM`的框架，所以最终调用不同版本可能各有不同，但是我这个版本调用的是`cap_bprm_set_creds`。
排除掉一堆乱七八糟的内容，对`euid/egid`有影响的逻辑只有这么一块：
```
/* Don't let someone trace a set[ug]id/setpcap binary with the revised
  * credentials unless they have the appropriate permit.
  *
  * In addition, if NO_NEW_PRIVS, then ensure we get no new privs.
  */
 is_setid = __is_setuid(new, old) || __is_setgid(new, old);


 if ((is_setid || __cap_gained(permitted, new, old)) &&
     ((bprm->unsafe & ~LSM_UNSAFE_PTRACE) ||
      !ptracer_capable(current, new->user_ns))) {
  /* downgrade; they get no more than they had, and maybe less */
  if (!ns_capable(new->user_ns, CAP_SETUID) ||
      (bprm->unsafe & LSM_UNSAFE_NO_NEW_PRIVS)) {
   new->euid = new->uid;
   new->egid = new->gid;
  }
  new->cap_permitted = cap_intersect(new->cap_permitted,
         old->cap_permitted);
 }
```
这一段逻辑的结果会导致`euid/egid`被重新赋值为`uid/gid`，先前`bprm_fill_uid`在`setuid/setgid`的情况下存在提升权限的可能，因此这儿就如注释所说又会降权。
关注一下条件，`is_setid`的结果取决于上一行`__is_setuid`和`__is_setgid`的或结果，内部逻辑是将新进程的`euid/egid`和当前进程的`uid/gid`作对比，看是否一致，倘若相等的话，说明执行的不是`setid`程序
```
static inline bool __is_setuid(struct cred *new, const struct cred *old)
{ return !uid_eq(new->euid, old->uid); }


static inline bool __is_setgid(struct cred *new, const struct cred *old)
{ return !gid_eq(new->egid, old->gid); }
```
`__cap_gained(permitted, new, old)`是关于linux的`capability`特性的方法，这个在之前的虚拟化里面略有涉及，简单来说就是超越`setid`这种非黑即白的更细化的权限限制机制。`_cap_gained`调用的其实是`cat_issubset`
```
#define __cap_gained(field, target, source) \
 !cap_issubset(target->cap_##field, source->cap_##field)
```
逻辑上简单来讲就是判断`target->cap_permitted`是否为`source->cap_permitted`的子集，而结合函数上下文来看的话，就是判断新进程的能力集是否是其父进程的能力集的子集，如果不是的话，说明要执行的程序被单独设置了新的能力集，这就可能存在越权的问题。
`bprm->unsafe & ~LSM_UNSAFE_PTRACE`需要结合先前的`check_unsafe_exec`一起说才行，这个函数会修改`bprm->unsafe`，倘若当前进程被`ptrace`的话，则需要将其与`LSM_UNSAFE_PTRACE`按位或运算
```
/* bprm->unsafe reasons */  
#define LSM_UNSAFE_SHARE 1  
#define LSM_UNSAFE_PTRACE 2 
#define LSM_UNSAFE_NO_NEW_PRIVS 4 
```
而到了`cap_bprm_set_creds`的逻辑判断中，通过和取反后的`LSM_UNSAFE_PTRACE`进行与操作，这儿的意义有点模糊，因为只要`bprm->unsafe`非0那结果就必然是`true`，而决定`bprm->unsafe`却不仅仅是`ptrace`，还有`task_no_new_privs(current)`和`p->fs->users > n_fs`，前者的意义是检测当前进程的`atomic_flags`是否为`PFA_NO_NEW_PRIVS`，这个好像涉及原子操作，放以后再说，后者则是检查当前进程的`fs_struct`引用数量是否大于线程组中具有相同`fs_struct`的线程数量和，如果大于的话说明当前进程是一个非安全的共享进程(多见于进程通信)。
```
static inline bool task_no_new_privs(struct task_struct *p)
{
    return test_bit(PFA_NO_NEW_PRIVS, &p->atomic_flags); //检测addr的第nr位是否为1
}
```
回归到条件判断中仅剩`!ptracer_capable(current, new->user_ns)`，看名字依然是关于`ptrace`的，这个函数的作用主要体现在`tracee`调用`execve`时，可见内核在这部分的安全校验上下了多大功夫，细看一下函数逻辑
```
/**
 * ptracer_capable - Determine if the ptracer holds CAP_SYS_PTRACE in the namespace
 * @tsk: The task that may be ptraced
 * @ns: The user namespace to search for CAP_SYS_PTRACE in
 *
 * Return true if the task that is ptracing the current task had CAP_SYS_PTRACE
 * in the specified user namespace.
 */
bool ptracer_capable(struct task_struct *tsk, struct user_namespace *ns)
{
 int ret = 0; /* An absent tracer adds no restrictions */
 const struct cred *cred;
 rcu_read_lock();
 cred = rcu_dereference(tsk->ptracer_cred);
 if (cred)
  ret = security_capable_noaudit(cred, ns, CAP_SYS_PTRACE);
 rcu_read_unlock();
 return (ret == 0);
}
```
除开`rcu`的部分不用理会外，核心又是一个`lsm`函数，其中的`cred`是`current->ptracer_cred`，即如果`current`确实被`ptrace`的话保存的就是其`tracer`的票据。`security_capable_noaudit`的检测逻辑如下：
```
 /* See if cred has the capability in the target user namespace
  * by examining the target user namespace and all of the target
  * user namespace's parents.
  */
 for (;;) {
  /* Do we have the necessary capabilities? */
  if (ns == cred->user_ns)
   return cap_raised(cred->cap_effective, cap) ? 0 : -EPERM;


  /*
   * If we're already at a lower level than we're looking for,
   * we're done searching.
   */
  if (ns->level <= cred->user_ns->level)
   return -EPERM;


  /* 
   * The owner of the user namespace in the parent of the
   * user namespace has all caps.
   */
  if ((ns->parent == cred->user_ns) && uid_eq(ns->owner, cred->euid))
   return 0;


  /*
   * If you have a capability in a parent user ns, then you have
   * it over all children user namespaces as well.
   */
  ns = ns->parent;
 }
```
第一个`if`主要用以检测`tracer`和`user namespace`和新进程的`namespace`是否相同，如果相同的话就去检测一下是`tracer`否有`CAP_SYS_PTRACE`能力，有则通过检查，第二个`if`则是判断如果新进程的`namespace`等级已经高于(越小越高)`tracer`的等级，那就直接不操作了直接返回错误`-EPERM(操作不允许)`，第三个`if`则是如果新进程的`父namespace`就是`tracer`的`namespace`并且`owner`和`tracer`权限相等的话，则通过检查，这儿的`for`循环主要是为了`ns = ns->parent`，不然存在那种新进程和`tracer`隔了几十个`user namespace`的情况。
> 这儿和`unsafe`部分的区别在于，`bprm->unsafe`发生在`current`主动去`attach`新的进程，而`ptracer_capable`则是发生在`current`发起`traceme`被`current->parent`追踪


那么这样再来看刚才的那整个条件判断，当一个`setid`的程序被执行，且执行者`trace`了这个新程序或者执行者发起了`traceme`但是`tracer`的权限不足时，就进入下一步检测
```
if (!ns_capable(new->user_ns, CAP_SETUID) ||
      (bprm->unsafe & LSM_UNSAFE_NO_NEW_PRIVS)) {
```
即如果新进程的`user namespace`中没有`CAP_SETUID`的权限或者`bprm->unsafe`的`LSM_UNSAFE_NO_NEW_PRIVS`位为1，即没有获取新权限能力，则降权，把权限重新降低为所有者权限。
> 这边分析的很乱，可能得抽空修改


这边有一个`PTRACE_TRACEME 本地提权漏洞`很值得学习一下。至此`prepare_binprm`中的权限设置部分就完结了


### `exec_binprm`
没有，略过


### `load_elf_binary`
这一部分就到了最终的权限设置的部分，上下遍历下来唯一的相关函数只有`install_exec_creds`
```
void install_exec_creds(struct linux_binprm *bprm)
{
 security_bprm_committing_creds(bprm);


 commit_creds(bprm->cred);
 bprm->cred = NULL;


 /*
  * Disable monitoring for regular users
  * when executing setuid binaries. Must
  * wait until new credentials are committed
  * by commit_creds() above
  */
 if (get_dumpable(current->mm) != SUID_DUMP_USER)
  perf_event_exit_task(current);
 /*
  * cred_guard_mutex must be held at least to this point to prevent
  * ptrace_attach() from altering our determination of the task's
  * credentials; any time after this it may be unlocked.
  */
 security_bprm_committed_creds(bprm);
 mutex_unlock(&current->signal->cred_guard_mutex);
}
EXPORT_SYMBOL(install_exec_creds);
```
先前的核心函数是`security_bprm_set_creds`，而这儿就是`security_bprm_committing_creds`了，同样的也是`LSM`的东西，不过好像并没有做什么改变的样子，因此实际上`cred`在这之前就已经是完全设置完了。而`commit_creds`逻辑代码挺长的，但是实际上的作用就是直接把传入的`cred`装载到当前进程上，甚至说很多内核提权的相关手段都是利用了此函数。


## 运行时权限变化
一个进程在启动后的权限就应当是固定的，而要去提升其权限，本质上就是修改其`task_struct`中的`euid/egid`值，然而这个值的位置又是在`内核内存`中，因此在一定的道理上说，只有`root`有能力提升一个已经在运行的程序权限，但是如果程序在运行过程中去`exec`一个`setid`的程序的话，就以进程本身来说其实是改变了权限的，但是进程逻辑其实也相应的发生了变化，不再是原本的进程。


# 后记
本来写这个实际上是想要开始涉足提权的部分，但是研究了一段时间发现时机还未到，所以就先写到这儿不写了。


# 参考资料
* [Linux进程与线程的区别](https://my.oschina.net/cnyinlinux/blog/422207)
* [Linux下的进程类别（内核线程、轻量级进程和用户进程）--Linux进程的管理与调度（四）](https://www.cnblogs.com/linhaostudy/p/9585506.html)
* [第十章：权限](https://www.kancloud.cn/thinkphp/linux-command-line/39440)
* [Linux之用户、权限的管理](https://www.jianshu.com/p/d190e0e84c8b)
* [Who Is Root? Why Does Root Exist?](https://www.tecmint.com/who-is-root-why-does-root-exist-in-linux/)
* [PTRACE_TRACEME 本地提权漏洞解析](https://www.iceswordlab.com/2019/11/28/CVE-2019-13272/)
* [linux cred管理](https://blog.csdn.net/Morphad/article/details/9089601)
* [sys_execv源碼分析](https://www.twblogs.net/a/5b8798032b71775d1cd7f0ff)
* [4.4 S_ISUID、S_ISGID位与文件访问权限检查](https://blog.csdn.net/zhoulaowu/article/details/14103599)
* [Linux的capability深入分析（1）](https://www.cnblogs.com/fengwei/p/4520876.html)
* [linux安全体系的文件权限管理](https://www.geek-share.com/detail/2605284802.html)
* [Linux系统ELF程序的执行过程](http://www.embeddedlinux.org.cn/emb-linux/system-development/201711/18-7791.html)
* [patch-00-27-introduce-credentials-ver-6](https://linux-security-module.vger.kernel.narkive.com/kGh8kBEs/patch-00-27-introduce-credentials-ver-6#post2)