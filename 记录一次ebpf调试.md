# 前言
> 真是太久没碰过`ebpf`和`kernel`的调试了，大概有快两年了，真是从搭环境开始，又从头到尾搞了一遍，我用的环境是`5.19.17`


事情的起因是朋友用`rust`写了一段`ebpf`的代码，然后吐槽`verifier`过不去，得依靠欺骗的方式才能成功，很扯淡。我说是不是`rust`的问题，让用`C`来写一个看看，结果依然是一样的问题，那么就不得不思考一下问题出在哪里了，可能是太久没接触`ebpf`了，很多东西都忘了，因此乍一看也没有发现代码有什么问题，那就只能调试了。
```
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>


char LICENSE[] SEC("license") = "Dual BSD/GPL";


// from vmlinux.h, bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
struct trace_event_raw_sys_enter {
    short unsigned int type;
    unsigned char flags;
    unsigned char preempt_count;
    int pid;
    int __syscall_nr;
    long unsigned int args[6];
    char __data[0];
};
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, unsigned int);
    __type(value, char [4096]);
} map SEC(".maps");


SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint__syscalls__sys_enter_execve(struct trace_event_raw_sys_enter *ctx)
{
    int pid = bpf_get_current_pid_tgid() >> 32;


    int key = 0 ;
    char *buf = (char *)bpf_map_lookup_elem(&map, &key);    // get ptr of inner buffer
    if (buf == 0)
        return 0;


    char *ptr_name = (char *)ctx->args[0];
    char **argv = (char **)ctx->args[1];
    char *ptr_argv0, *ptr_argv1;
    bpf_probe_read(&ptr_argv0, sizeof(ptr_argv0), argv + 0);
    bpf_probe_read(&ptr_argv1, sizeof(ptr_argv1), argv + 1);


    /* read filename into buffer */
    unsigned int offset = bpf_probe_read_str(buf, 4096, ptr_name);




    /* read argv0 into buffer */
    if (offset > 4096 || offset < 0)
        return 0;
    int len = bpf_probe_read_str(buf + offset, 4096 - offset, ptr_argv0);
    bpf_printk("len : %d\n", len);
    return 0;
}
```
代码大概是这个样子，正常加载的话最后总是会出现这样的问题：
```
; int len = bpf_probe_read_str(buf + offset, tmpoff, ptr_argv0);
65: (bf) r1 = r6                      ; R1_w=map_value(off=0,ks=4,vs=4096,umax=4096,var_o)
66: (bf) r2 = r9                      ; R2_w=scalar(id=8,umax=8191,var_off=(0x0; 0x1fff)))
67: (85) call bpf_probe_read_str#45
invalid access to map value, value_size=4096 off=0 size=8191
R1 min value is outside of the allowed memory range
```
可以看到说是越界了，但是回顾代码来看，`offset`是被控制到了`0`到`4096`之间才对，而一个`map`的大小也是`4096`，不应该会产生越界啊，是不是`vertifier`有什么独特的检测逻辑是已经被我所忘却或者是`verifier`本身存在问题呢？


带着这个疑问开始了我的调试之旅


# 定位
根据报错很好定位到出现错误的地方
```
/* check read/write into a memory region with possible variable offset */
static int check_mem_region_access(struct bpf_verifier_env *env, u32 regno,
                   int off, int size, u32 mem_size,
                   bool zero_size_allowed)
{
    ......
    err = __check_mem_access(env, regno, reg->smin_value + off, size,
                 mem_size, zero_size_allowed);
    if (err) {
        verbose(env, "R%d min value is outside of the allowed memory range\n",
            regno);
        return err;
    }
    ......
}
```
可以看到是`__check_mem_access`这个检查没有通过，导致`verifier`认为读写越界从而产生错误，而这个函数其实仅有一个判断：
```
    bool size_ok = size > 0 || (size == 0 && zero_size_allowed);
    if (off >= 0 && size_ok && (u64)off + size <= mem_size)
        return 0;
```
如果这个条件不满足的话，就会根据具体的`reg->type`而输出对应的错误，就如调试的这份代码是在读写一个`PTR_TO_MAP_VALUE`，因此可以明显看到相应的报错
```
invalid access to map value, value_size=4096 off=0 size=819
```
那么回到入参的地方，检查一下实际入参和预期值是否相同


| check_mem_region_access | __check_mem_access | value |
| ------------------------------------- | ------------------------------- | ------- |
| reg->smin_value + off | off | 0x0 |
| size | size | 0x1fff |
| mem_size | mem_size | 0x1000 |
| zero_size_allowed | zero_size_allowed | 0x1 |
|| size_ok | 0x1 |
|| off >= 0 | 0x1 |
|| (u64)off + size <= mem_size | 0x0 |


可以明显的看到，`(u64)off + size <= mem_size`的计算结果除了问题，而`mem_size`的值又是没问题的，这个代表的是`map_value`的大小，确实就是如我们设置的`4096`，而`off`的值都是`0x0`了也是没有问题的，那么只有`size`一个值出现了异常，并且也确实是一个超出预期的`8191(4096 + 4095)`


那就看一下`size`究竟是从何而来？通过`backtrace`看一下函数调用栈，然后挨个往上回溯
```
#0  check_mem_region_access (env=env@entry=0xffff88810d1f8000, regno=regno@entry=0x1, off=off@entry=0x0, 
    size=size@entry=0x1fff, mem_size=0x1000, zero_size_allowed=0x1) at kernel/bpf/verifier.c:3574
#1  0xffffffff8152006c in check_map_access (env=env@entry=0xffff88810d1f8000, regno=regno@entry=0x1, off=0x0, 
    size=size@entry=0x1fff, zero_size_allowed=0x1, src=src@entry=ACCESS_HELPER) at kernel/bpf/verifier.c:3801
#2  0xffffffff815224a8 in check_helper_mem_access (env=env@entry=0xffff88810d1f8000, regno=regno@entry=0x1, 
    access_size=access_size@entry=0x1fff, zero_size_allowed=zero_size_allowed@entry=0x1, 
    meta=meta@entry=0x0 <fixed_percpu_data>) at kernel/bpf/verifier.c:5203
#3  0xffffffff81526939 in check_mem_size_reg (env=env@entry=0xffff88810d1f8000, reg=reg@entry=0xffff88810811f0f0, 
    regno=regno@entry=0x2, zero_size_allowed=0x1, meta=0x0 <fixed_percpu_data>) at kernel/bpf/verifier.c:5296
#4  0xffffffff8154cea0 in check_func_arg (fn=0xffffffff844ada00 <bpf_probe_read_compat_str_proto>, 
    meta=0xffffc900017a70a8, arg=0x1, env=<optimized out>) at kernel/bpf/verifier.c:6035
#5  check_helper_call (env=env@entry=0xffff88810d1f8000, insn=insn@entry=0xffffc9000154c260, 
    insn_idx_p=insn_idx_p@entry=0xffff88810d1f8000) at kernel/bpf/verifier.c:7192
#6  0xffffffff815592dc in do_check (env=<optimized out>) at kernel/bpf/verifier.c:12234
#7  do_check_common (env=env@entry=0xffff88810d1f8000, subprog=subprog@entry=0x0) at kernel/bpf/verifier.c:14410
#8  0xffffffff8156a37d in do_check_main (env=0xffff88810d1f8000) at kernel/bpf/verifier.c:14473
#9  bpf_check (prog=prog@entry=0xffffc900017a7770, attr=attr@entry=0xffffc900017a79e8, uattr=...)
    at kernel/bpf/verifier.c:15042
#10 0xffffffff81507242 in bpf_prog_load (attr=attr@entry=0xffffc900017a79e8, uattr=...) at kernel/bpf/syscall.c:2575
#11 0xffffffff8150cdd3 in __sys_bpf (cmd=cmd@entry=0x5, uattr=..., size=size@entry=0x8c) at kernel/bpf/syscall.c:4919
#12 0xffffffff81510508 in ____bpf_sys_bpf (attr_size=0x8c, attr=0xffff88810c925438, cmd=0x5)
    at kernel/bpf/syscall.c:5052
#13 bpf_sys_bpf (cmd=0x5, attr=0xffff88810c925438, attr_size=0x8c, __ur_1=<optimized out>, __ur_2=<optimized out>)
    at kernel/bpf/syscall.c:5038
#14 0xffffffffc001b567 in ?? ()
#15 0xffff88810c97ae80 in ?? ()
#16 0x1ffff920002f4f83 in ?? ()
#17 0x0000000000000418 in ?? ()
#18 0x0000000000000005 in fixed_percpu_data ()
#19 0x0000000000000000 in ?? ()
```
通过一番溯源，最后定位到了这个值是来源于`check_mem_size_reg`这个函数中的`reg->umax_value`，通过查看当前状态下此`reg`的地址和`env->cur_state->frame[0x0]->regs`中的寄存器集合的地址对比以后，可以发现此寄存器是`r2`寄存器，结合`llvm-objdump`反汇编一下`ebpf`程序查看对应的字节码以及加载时候的报错，可以确定出现问题的是`bpf_probe_read_str`的第二个参数，也就是`4096 - offset`
查看相应的寄存器情况，可以看到`verifier`给`tmpoff`预测的数值分布区间是这样的
```
  var_off = {
    value = 0x0,
    mask = 0x1fff
  },
  smin_value = 0x0,
  smax_value = 0x1fff,
  umin_value = 0x0,
  umax_value = 0x1fff,
  s32_min_value = 0x0,
  s32_max_value = 0x1fff,
  u32_min_value = 0x0,
  u32_max_value = 0x1fff,
```
然而这其实是不符合我们的预期的，因为在我们的预期中，`offset`是一个无符号整型，并且是一个`0 <= offset <= 4096`，那么`4096 - offset`的预期值应当是`0x0 - 0x1000`才是，而非`0x1fff`


# `0x1000` OR `0x1fff`


为了保险起见，再观察一下第一个入参给出来的预测值的情况看是否满足预期，结果很有意思的一点出现了，就是在计算`buf + offset`的时候，这两个值居然都是符合预期的。
```
buf = {
  type = PTR_TO_MAP_VALUE,
  ......
  var_off = {
    value = 0x0,
    mask = 0x0
  },
  smin_value = 0x0,
  smax_value = 0x0,
  umin_value = 0x0,
  umax_value = 0x0,
  s32_min_value = 0x0,
  s32_max_value = 0x0,
  u32_min_value = 0x0,
  u32_max_value = 0x0,
  ......
}
offset = {
  type = SCALAR_VALUE,
  ......
  var_off = {
    value = 0x0,
    mask = 0x1fff
  },
  smin_value = 0x0,
  smax_value = 0x1000,
  umin_value = 0x0,
  umax_value = 0x1000,
  s32_min_value = 0x0,
  s32_max_value = 0x1000,
  u32_min_value = 0x0,
  u32_max_value = 0x1000,
  ......
}
```
> 反汇编可以看到`buf + offset`的字节码是`r6 += r1`，而在`verifier`中对于寄存器的值预估基本都要经过`adjust_reg_min_max_vals`，因此可以这么下个断点`b adjust_reg_min_max_vals if insn->dst_reg == 0x6 && insn->src_reg == 0x1`


那既然如此，就再观察一下第二个入参`4096 - offset`在计算前的情况
```
4096 = {
  type = SCALAR_VALUE,
  ......
  var_off = {
    value = 0x1000,
    mask = 0x0
  },
  smin_value = 0x1000,
  smax_value = 0x1000,
  umin_value = 0x1000,
  umax_value = 0x1000,
  s32_min_value = 0x1000,
  s32_max_value = 0x1000,
  u32_min_value = 0x1000,
  u32_max_value = 0x1000,
  .......
}
offset = {
  type = SCALAR_VALUE,
  ......
  var_off = {
    value = 0x0,
    mask = 0xffffffffffffffff
  },
  smin_value = 0xfffffffffffff001,
  smax_value = 0x1000,
  umin_value = 0x0,
  umax_value = 0xffffffffffffffff,
  s32_min_value = 0xfffff001,
  s32_max_value = 0x1000,
  u32_min_value = 0x0,
  u32_max_value = 0xffffffff,
  ......
}
```
这次的`offset`居然和第一个入参时候不同！
重新观察寄存器，第一个传参时候`offset`的寄存器是`r1`，而到了第二个传参时候`offset`的寄存器居然是`r0`，这显然是有问题的，因为`r1`是经过了`if`判断重新限制了范围的，而`r0`却没有
```
      28:    85 00 00 00 2d 00 00 00    call 45  // unsigned int offset = bpf_probe_read_str(buf, 4096, ptr_name)
      29:    bf 01 00 00 00 00 00 00    r1 = r0
      30:    67 01 00 00 20 00 00 00    r1 <<= 32
      31:    77 01 00 00 20 00 00 00    r1 >>= 32
      32:    25 01 0b 00 00 10 00 00    if r1 > 4096 goto +11 <LBB0_3>
      33:    1f 08 00 00 00 00 00 00    r8 -= r0 // 这个offset是没有经过if判断的
      34:    0f 16 00 00 00 00 00 00    r6 += r1
      35:    79 a3 f0 ff 00 00 00 00    r3 = *(u64 *)(r10 - 16)
      36:    bf 61 00 00 00 00 00 00    r1 = r6
      37:    bf 82 00 00 00 00 00 00    r2 = r8
      38:    85 00 00 00 2d 00 00 00    call 45
```
那么很明显，是编译出了问题，很重要的条件被忽略了，最终导致了这个结果


# 后记
整完以后给`llvm`提了一个[issue](https://github.com/llvm/llvm-project/issues/62849)，可惜就再也没有下文了










