> 代码注入ELF的核心就是`代码注入`，也就是把`ELF`直接注入到某段内存中执行，这样的话对于文件系统来说就没有实体文件产生。当然，在此技术之上，又有执行时绕过`audit`检测的方式，这个放到后面说。

linux中有个函数叫`ptrace`，这个函数提供了一种父进程控制子进程运行，并检查和更改的能力。这个函数主要用于实现断点调试。一个被调试的进程收到一个信号则进程中止，然后通知父进程，在进程中止状态下，进程的内存空间可以被读写，而父进程可以使得子进程继续执行，并选择是否忽略中止的信号。
简单一点说就是在一个进程运行过程中依然具有针对该进程的控制权，总的来说就是任意读写`task_struct`，`内存`和`寄存器`。

`ptrace`的使用还是有内核提供了帮助，也就是在`ptrace`环境中，程序在执行系统调用前，内核会检测该进程是否被`Trace`，对于已经被`trace`的程序内核会暂停该程序，然后把控制权转交给`Tracer`，从而达到让一个程序控制另一个程序。
```
static int ptrace_check_attach(struct task_struct *child, bool ignore_state)
{
 int ret = -ESRCH;

 /*
  * We take the read lock around doing both checks to close a
  * possible race where someone else was tracing our child and
  * detached between these two checks. After this locked check,
  * we are sure that this is our traced child and that can only
  * be changed by us so it's not changing right after this.
  */
 read_lock(&tasklist_lock);
 if (child->ptrace && child->parent == current) {
  WARN_ON(child->state == __TASK_TRACED);
  /*
   * child->sighand can't be NULL, release_task()
   * does ptrace_unlink() before __exit_signal().
   */
  if (ignore_state || ptrace_freeze_traced(child))
   ret = 0;
 }
 read_unlock(&tasklist_lock);

 if (!ret && !ignore_state) {
  if (!wait_task_inactive(child, __TASK_TRACED)) {
   /*
    * This can only happen if may_ptrace_stop() fails and
    * ptrace_stop() changes ->state back to TASK_RUNNING,
    * so we should not worry about leaking __TASK_TRACED.
    */
   WARN_ON(child->state == __TASK_TRACED);
   ret = -ESRCH;
  }
 }

 return ret;
}
```
而`trace`方式也有两种：
1. `tracer`是`tracee`的父进程，`tracee`主动调用`ptrace(PTRACE_TRACEME,0,0,0)`
2. 进程`tracer`主动调用`ptrace(PTRACE_ATTACH,trace->pid,0,0)`

他们都可以建立起一个`ptrace`关系，即`tracee->ptrace&&tracee->parent == tracer`

就以一个父子进程为例：
通过`fork()`创建的进程虽然在父进程中可以返回一个子进程的`pid`，但是两个进程就独立的两个逻辑，各有各的方法。
```
int main()
{
    pid_t child;
    long orig_rax;
    child = fork();
    if(child == 0)
    {
        printf("i am child\n");
        execl("/usr/bin/whoami", "", NULL);
    }
    else 
    {
        wait(NULL);
        printf("i am dad\n");
    }
    return 0;
}
```
就像是这样的一段代码，结果也是很明显，`子进程`输出一段字符串还有`whoami`的执行结果，接着`父进程`输出字符串。
那通过`ptrace`在父进程中修改子进程的输出。
> 在 x86-64 上，系统调用号是在 rax 中传递的，而用户模式下参数是在 rdi、rsi、rdx、r8 和 r9 中传递的。内核接口的系统调用则是rdi,rsi,rdx,r10,r8和r9。

父进程对子进程检查完后自然需要让子进程继续运行，`ptrace`中有4种方式：
1. `PTRACE_CONT`
2. `PTRACE_SYSCALL`
3. `PTRACE_SINGLESTEP`
4. `PTRACE_DETACH`

## 系统调用

其中`PTRACE_SYSCALL`是常用的一种，也就是针对子进程的`系统调用`进行检查。
```
从 Tracer 的角度而言， Tracee 就如同受到了SIGTRAP被停止了一样。因此PTRACE_SYSCALL一种用法是：在进入系统调用时检测参数；在离开此次调用时，检测其返回值。
```

![6cd46334-b27b-4b2c-8b8d-bfc75d803297.png](病毒与调试技术-代码注入ELF_files/6cd46334-b27b-4b2c-8b8d-bfc75d803297.png)

这儿倒也没什么坑点，就是单纯的找偏移，提数据，覆盖数据，这样就能修改掉系统调用的执行参数。

## 注入代码
> 更多的用法是代码注入，也就是把B代码的逻辑注入到A中，执行A的时候也就会执行B的代码逻辑。如果结合上`memfd_create`也就做到了无文件渗透，且能绕过`audit`监控。

涉及到代码注入，就得先明白一个程序是什么，这样才能知道怎么注入，这一部分其实主要是`汇编`的知识。

一段`C代码`经过编译链接后最终生成了一个`ELF`文件：
1. 可重定向文件：文件保存着代码和适当的数据，用来和其他的目标文件一起来创建一个可执行文件或者是一个共享目标文件。（目标文件或者静态库文件，即linux通常后缀为.a和.o的文件）
2. 可执行文件：文件保存着一个用来执行的程序。（例如bash，gcc等）
3. 共享目标文件：共享库。文件保存着代码和合适的数据，用来被下连接编辑器和动态链接器链接。（linux下后缀为.so的文件。）
4. 核心转储文件：进程意外中止时可以将进程地址空间内容及终止时的一些其余信息转储到核心转储文件。

周知，`指令`和`数据`都是得进内存的，那么一个`ELF`是怎么被加载进内存的。

一个程序的执行在内核中基本都绕不开`do_execve()`这个函数，当然也是`do_execveat_common`：
```
int do_execve(struct filename *filename,
 const char __user *const __user *__argv,
 const char __user *const __user *__envp)
{
 struct user_arg_ptr argv = { .ptr.native = __argv };
 struct user_arg_ptr envp = { .ptr.native = __envp };
 return do_execveat_common(AT_FDCWD, filename, argv, envp, 0);
}
```
> `do_execveat_common`很长，不展示代码

这个函数中构建了一个来自于`LSM`定义的结构体`struct linux_binprm`，保存了载入二进制文件的各种参数。然后通过`exec_binprm()`来执行，跟进去看此函数：
```
static int exec_binprm(struct linux_binprm *bprm)
{
 pid_t old_pid, old_vpid;
 int ret;

 /* Need to fetch pid before load_binary changes it */
 old_pid = current->pid;
 rcu_read_lock();
 old_vpid = task_pid_nr_ns(current, task_active_pid_ns(current->parent));
 rcu_read_unlock();

 ret = search_binary_handler(bprm);
 if (ret >= 0) {
  audit_bprm(bprm);
  trace_sched_process_exec(current, old_pid, bprm);
  ptrace_event(PTRACE_EVENT_EXEC, old_vpid);
  proc_exec_connector(current);
 }

 return ret;
}
```
这个函数中的核心功能是`search_binary_handler`可以根据不同的文本格式选择不同的load函数。`elf`的`load_binary`方法如下：
```
static struct linux_binfmt elf_format = {
 .module = THIS_MODULE,
 .load_binary = load_elf_binary,
 .load_shlib = load_elf_library,
 .core_dump = elf_core_dump,
 .min_coredump = ELF_EXEC_PAGESIZE,
};
```
继续跟到`load_elf_binary`的函数里，非常的长就简单说。
```
/* sizeof(linux_binprm->buf) */
#define BINPRM_BUF_SIZE 128
loc->elf_ex = *((struct elfhdr *)bprm->buf);
```
这一段作用是获取了ELF的前128字节作为`exec-header`，接着就是校验部分：
```
if (memcmp(loc->elf_ex.e_ident, ELFMAG, SELFMAG) != 0)
  goto out;
 if (loc->elf_ex.e_type != ET_EXEC && loc->elf_ex.e_type != ET_DYN)
  goto out;
 if (!elf_check_arch(&loc->elf_ex))
  goto out;
 if (elf_check_fdpic(&loc->elf_ex))
  goto out;
 if (!bprm->file->f_op->mmap)
  goto out;
```
从上往下分别校验的是：
1. `unsigned char e_ident[EI_NIDENT]; /* ELF "magic number" */`，检测当前`ELF`文件的`magic number`(前4个字节)是否为`\177ELF`(8进制)，换成16进制就是`0x7F E L F`
2. 判断当前`ELF`类型是否为`ET_EXEC(可执行文件)`或者是`ET_DYN(动态链接库文件)`
3. 确认硬件平台信息，主要是涉及到交叉编译相关的东西
4. 这个追源码发现函数定义就是`false`和`0`，所以不太清楚什么意义，看名字可能和`FDPIC ELF`有关
```
Executable file formats:
Files can be in two basic formats in the Blackfin Linux world:
FLAT
Binary Flat files commonly known as BFLT, are a relatively simple and lightweight executable format based on the original a.out format. BFLT files are the default file format in embedded Linux.
FDPIC ELF
The executable and linking format (ELF) was originally developed by Unix System Laboratories and has become the standard in file formats. TheELF standard has greater power and more flexibility than the BFLT format. However, they are more heavyweight, requiring more disk space and having a small run-time penalty.
Both formats support static and dynamic linking (shared libraries), although it is much easier to use and create shared libraries withELF. OnlyELF supports dynamic loading (dlopen(),dlsym(), dlclose()), and the standard method for creating and maintaining shared libraries. （For more information on libraries, see thecreating libraries page.）
Keep in mind that under Linux, we use the FDPIC ELF format. The difference between the FDPICELF format and theELF format is merely in the internals (how the PLT is implemented) as a requirement for working without an MMU. For all intents and purposes from the programmer's perspective, the ELF is anELF.
```
5. 判断当前`elf`文件的操作集是否存在，感觉没什么用

过了校验后，就是针对程序头表的加载：
```
elf_phdata = load_elf_phdrs(&loc->elf_ex, bprm->file);
 if (!elf_phdata)
  goto out;
```
这里面主要的判断就是判断加载进来的`elf`文件是否有超过`1`个段且所有段和是否不大于`64kb`，如果符合的话就调用`kernel_read`(不清楚干嘛用的，看名字像是读入指定长度信息)
```
 /* Sanity check the number of program headers... */
 if (elf_ex->e_phnum < 1 ||
  elf_ex->e_phnum > 65536U / sizeof(struct elf_phdr))
  goto out;
 /* Read in the program headers */
 retval = kernel_read(elf_file, elf_phdata, size, &pos);
```
加载完程序头表后接着就开始处理解释器(动态连接器)，通过遍历寻找到`PT_INTERP`类型的段，如果存在的话说明需要动态链接，会通过`kernel_read`读入段内容，直观来看得话这是一个`动态链接库路径`，读入后会用`open_exec`打开，之后再将`loc->interp_elf_ex`设置为解释器的头部在缓存中的起始地址。
在针对解释器加载前会有一段堆栈检查：
```
static int load_elf_binary(struct linux_binprm *bprm)
{
    ...

    elf_ppnt = elf_phdata;
    for (i = 0; i < loc->elf_ex.e_phnum; i++, elf_ppnt++)
        switch (elf_ppnt->p_type) {
        case PT_GNU_STACK:
            if (elf_ppnt->p_flags & PF_X)
                executable_stack = EXSTACK_ENABLE_X;
            else
                executable_stack = EXSTACK_DISABLE_X;
            break;

        case PT_LOPROC ... PT_HIPROC:
            retval = arch_elf_pt_proc(&loc->elf_ex, elf_ppnt,
                          bprm->file, false,
                          &arch_state);
            if (retval)
                goto out_free_dentry;
            break;
        }

    ...
}
```
以旧是遍历查找到`PT_GNU_STACK`的段，检查堆栈是否可执行，根据结果设置executable_stack。
接着就是开始加载解释器，开始作校验
```
 /* Some simple consistency checks for the interpreter */
 if (elf_interpreter) {
  retval = -ELIBBAD;
  /* Not an ELF interpreter */
  if (memcmp(loc->interp_elf_ex.e_ident, ELFMAG, SELFMAG) != 0)
   goto out_free_dentry;
  /* Verify the interpreter has a valid arch */
  if (!elf_check_arch(&loc->interp_elf_ex) ||
      elf_check_fdpic(&loc->interp_elf_ex))
   goto out_free_dentry;

  /* Load the interpreter program headers */
  interp_elf_phdata = load_elf_phdrs(&loc->interp_elf_ex,
         interpreter);
  if (!interp_elf_phdata)
   goto out_free_dentry;

  /* Pass PT_LOPROC..PT_HIPROC headers to arch code */
  elf_ppnt = interp_elf_phdata;
  for (i = 0; i < loc->interp_elf_ex.e_phnum; i++, elf_ppnt++)
   switch (elf_ppnt->p_type) {
   case PT_LOPROC ... PT_HIPROC:
    retval = arch_elf_pt_proc(&loc->interp_elf_ex,
         elf_ppnt, interpreter,
         true, &arch_state);
    if (retval)
     goto out_free_dentry;
    break;
   }
 }
```
和`ELF`程序的加载check差不多，检查完后通过`load_elf_phdrs`加载入解释器的头表。
接着就是比较重要的部分，涉及到堆栈初始化的东西：
```
 /* Flush all traces of the currently running executable */
 retval = flush_old_exec(bprm);
 if (retval)
  goto out_free_dentry;
 /* Do this immediately, since STACK_TOP as used in setup_arg_pages
    may depend on the personality. */
 SET_PERSONALITY2(loc->elf_ex, &arch_state);
 if (elf_read_implies_exec(loc->elf_ex, executable_stack))
  current->personality |= READ_IMPLIES_EXEC;

 if (!(current->personality & ADDR_NO_RANDOMIZE) && randomize_va_space)
  current->flags |= PF_RANDOMIZE;

 setup_new_exec(bprm);
 install_exec_creds(bprm);

 /* Do this so that we can load the interpreter, if need be. We will
    change some of these later */
 retval = setup_arg_pages(bprm, randomize_stack_top(STACK_TOP),
     executable_stack);
 if (retval < 0)
  goto out_free_dentry;
	
 current->mm->start_stack = bprm->p;
```
`flush_old_exec`是用来清理当前进程的所有线程并清空内存空间重置状态的，接着设置`task_struct`的`personality(平台信息)`，然后通过`setup_new_exec(bprm);`对地址空间进行初始化，主要是由`arch_pick_mmap_layout`负责内存布局，比如栈地址增长之类的。
下一行是新引入的安全函数，这是`LSM`的`HOOK POINT`，不会对过程有多大的影响。
```
install_exec_creds(bprm);
```
当完成地址空间初始化后，就可以通过`setup_arg_pages`函数创建栈了。系统给进程栈分配的起始地址是`STACK_TOP`，这个值一般都是`TASK_SIZE`，但是如果内核中设置了`PF_RANDOMIZE`(ASLR机制)这样的话进程栈的起始地址是`STACK_TOP - randomized_variable`
> 不过这是基于栈自顶向下增长，如果设置了CONFIG_STACK_GROWSUP，那栈起始地址就是`STACK_TOP + randomized_variable`

这个函数还做了很多其余的操作，具体的详情有点看不动，就记录下作用：
```
一个新的映像要能运行，用户空间堆栈是必须的，所以首先要把用户空间的一个虚拟地址区间划出来用于堆栈。进一步，当CPU进入新映像的程序入口时，堆栈上应该有argc、argv[]、envc、envp[]等参数。这些参数来自老的程序，需要通过堆栈把它们传递给新的映像。实际上，argv[]和envp[]中是一些字符串指针，光把指针传给新映像，而不把相应的字符串传递给新映像，那是毫无意义的。为此，在进入search_binary_handler()、从而进入load_elf_binary()之前，do_execve()已经为这些字符串分配了若干页面，并通过copy_strings()从用户空间把这些字符串拷贝到了这些页面中。现在则要把这些页面再映射回用户空间(当然是在不同的地址上)，这就是这里setup_arg_pages()要做的事。
```
至此开始将`ELF`加载入内存，过程类似与之前的方式也是通过遍历找到`PT_LOAD`标记的段，然后生成`BSS`信息
```
retval = set_brk(elf_bss + load_bias,
      elf_brk + load_bias,
      bss_prot);
```
接着根据段header的flag标志位设置内存的标志位`elf_prot`
```
  if (elf_ppnt->p_flags & PF_R)
   elf_prot |= PROT_READ;
  if (elf_ppnt->p_flags & PF_W)
   elf_prot |= PROT_WRITE;
  if (elf_ppnt->p_flags & PF_X)
   elf_prot |= PROT_EXEC;
```
接下来判断需要加载的文件数据类型，如果是`ET_EXEC`则在固定位置上分配虚拟内存，加上`MAP_FIXED`标志，如果类型为`ET_DYN`则需要在进行地址映射的时候加上`arch_mmap_rnd()`的随机数，将偏移记录到`load_bias`中，`total_sizre`为需要映射的内存大小。
```
  if (loc->elf_ex.e_type == ET_EXEC || load_addr_set) {
   elf_flags |= MAP_FIXED;
  } else if (loc->elf_ex.e_type == ET_DYN) {
   /*
    * This logic is run once for the first LOAD Program
    * Header for ET_DYN binaries to calculate the
    * randomization (load_bias) for all the LOAD
    * Program Headers, and to calculate the entire
    * size of the ELF mapping (total_size). (Note that
    * load_addr_set is set to true later once the
    * initial mapping is performed.)
    *
    * There are effectively two types of ET_DYN
    * binaries: programs (i.e. PIE: ET_DYN with INTERP)
    * and loaders (ET_DYN without INTERP, since they
    * _are_ the ELF interpreter). The loaders must
    * be loaded away from programs since the program
    * may otherwise collide with the loader (especially
    * for ET_EXEC which does not have a randomized
    * position). For example to handle invocations of
    * "./ld.so someprog" to test out a new version of
    * the loader, the subsequent program that the
    * loader loads must avoid the loader itself, so
    * they cannot share the same load range. Sufficient
    * room for the brk must be allocated with the
    * loader as well, since brk must be available with
    * the loader.
    *
    * Therefore, programs are loaded offset from
    * ELF_ET_DYN_BASE and loaders are loaded into the
    * independently randomized mmap region (0 load_bias
    * without MAP_FIXED).
    */
   if (elf_interpreter) {
    load_bias = ELF_ET_DYN_BASE;
    if (current->flags & PF_RANDOMIZE)
     load_bias += arch_mmap_rnd();
    elf_flags |= MAP_FIXED;
   } else
    load_bias = 0;

   /*
    * Since load_bias is used for all subsequent loading
    * calculations, we must lower it by the first vaddr
    * so that the remaining calculations based on the
    * ELF vaddrs will be correctly offset. The result
    * is then page aligned.
    */
   load_bias = ELF_PAGESTART(load_bias - vaddr);

   total_size = total_mapping_size(elf_phdata,
       loc->elf_ex.e_phnum);
   if (!total_size) {
    retval = -EINVAL;
    goto out_free_dentry;
   }
  }
```
记录完这些后就可以通过`elf_map`将文件映射到虚拟内存中，如果是第一次映射的话，则需要记录装载地址`load_addr`，如果是`ET_DYN`类型的数据，则需要加上偏移`load_bias`：
```
  if (!load_addr_set) {
   load_addr_set = 1;
   load_addr = (elf_ppnt->p_vaddr - elf_ppnt->p_offset);
   if (loc->elf_ex.e_type == ET_DYN) {
    load_bias += error -
                 ELF_PAGESTART(load_bias + vaddr);
    load_addr += load_bias;
    reloc_func_desc = load_bias;
   }
  }
```
每次映射完都需要修改每个段的起始位置，从虚拟地址内存中看，从低地址到高地址依次是`代码段`，`数据段`，`BSS段`和`堆`，每次循环都加上一个偏移：
```
 elf_bss += load_bias;
 elf_brk += load_bias;
 start_code += load_bias;
 end_code += load_bias;
 start_data += load_bias;
 end_data += load_bias;
```
> `start_code`和`end_code`是`代码段`的起止地址，`start_data`和`end_data`是`数据段`，`start_brk`是堆，`elf_bss`是`bss段`的起始地址，`elf_brk`是`bss段`的终止地址

```
retval = set_brk(elf_bss, elf_brk, bss_prot);
```
分配`BSS`段的内存空间。后面的代码大概就是设置各种参数变量信息，例如在新进程中设置各种段的位置：
```
 current->mm->end_code = end_code;
 current->mm->start_code = start_code;
 current->mm->start_data = start_data;
 current->mm->end_data = end_data;
 current->mm->start_stack = bprm->p;
```
最后调用`start_thread`设置程序入口，准备执行：
```
start_thread(regs, elf_entry, bprm->p);
```
其中程序运行的位置为`elf_entry`，而`bprm->p`是进程栈顶。

由此可知的是：
1. 从内核态返回用户态时，程序的入口被放在了`rip(指令寄存器)`中
2. 动态编译的程序入口是解释器镜像入口，静态编译程序入口是本身镜像入口地址
3. 对于运行的程序来说只有`代码段`，`数据段`，`BSS`段，`堆`，`栈`，段中还有不同的节，比如`.rodata`就是`.text`段中的一节。

![ad526cf1-049b-4a88-8edf-32b471ef22ec.png](病毒与调试技术-代码注入ELF_files/ad526cf1-049b-4a88-8edf-32b471ef22ec.png)

## 代码注入
这部分实际是研究了的，但是其实很大一部分知识都是病毒相关的东西，因此有点走远了，所以并不想深入研究过去。
说一下要点：
1. 必须得学会写shellcode，其中关于这部分的坑点主要在于`AT&T`和`Intel`格式的问题，还有就是需要在中间不能有`\x00`，因此要注意针对寄存器的操作
2. 代码必须注入到程序的可执行段，即具备`X`权限的位置

更具体的还是直接看代码吧。
# 参考
* [Ptrace--Linux中一种代码注入技术的应用](https://blog.csdn.net/litost000/article/details/82813641)
* [[ptrace修改内存]实现进程代码注入](https://blog.csdn.net/u011580175/article/details/82831889)
* [In-Memory-Only ELF Execution (Without tmpfs)](https://magisterquis.github.io/2018/03/31/in-memory-only-elf-execution.html)
* [ptrace](https://github.com/QAX-A-Team/ptrace)
* [ptrace理解](https://www.cnblogs.com/mysky007/p/11047943.html)
* [ptrace系统调用的实现](https://blog.csdn.net/imred/article/details/90141080)
* [linux下64位汇编的系统调用(2)](https://www.bbsmax.com/A/q4zVkYp2JK/)
* [Where did fork go?](https://thorstenball.com/blog/2014/06/13/where-did-fork-go/)
* [modifying-system-call-arguments-with-ptrace](https://www.alfonsobeato.net/c/modifying-system-call-arguments-with-ptrace/)
* [Linux无文件渗透执行ELF](https://www.secpulse.com/archives/70269.html)
* [ELF文件结构描述](https://www.cnblogs.com/linhaostudy/p/8855238.html)
* [为什么main函数的局部变量的地址每次运行不一样？](http://www.voidcn.com/article/p-mxfficqv-bdu.html)
* [深入Linux内核架构——进程虚拟内存](https://www.cnblogs.com/holyxp/p/10016582.html)
* [load_elf_binary阅读(1)](http://blog.chinaunix.net/uid-29512885-id-4274390.html)
* [Linux加载启动可执行程序的过程（一）内核空间加载ELF的过程](https://blog.csdn.net/chrisnotfound/article/details/80082289)
* [这个gcc编译器命令的-z选项是什么？](http://www.voidcn.com/article/p-fgksaypt-bup.html)
* [Linux Process Virtual Memory](http://www.bubuko.com/infodetail-779546.html)
* [linux病毒技术之data段感染](https://xz.aliyun.com/t/5336)
* [向正在运行的Linux应用程序注入代码](https://www.freebuf.com/articles/system/6388.html)
* [ELF病毒分析](https://xz.aliyun.com/t/2254)
* [[Ptrace]Linux内存替换（五）x86_64平台代码注入](https://blog.csdn.net/Dearggae/article/details/47450739?locationNum=10)
* [GUN C内联汇编](https://blog.csdn.net/u011580175/article/details/82713801)
* [Linux 汇编语言开发指南](https://www.ibm.com/developerworks/cn/linux/l-assembly/index.html)
* [Linux下shellcode的编写](https://xz.aliyun.com/t/2052)
* [寄存器](https://www.jianshu.com/p/57128e477efb)
* [Linux x64下编写shellcode - execve(/bin/sh)](https://www.jianshu.com/p/e21dcba5668f)