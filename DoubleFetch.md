> 又到了研究漏洞的时候了


先前有探讨过`kernel`中的同步机制，一个`临界区`的访问应当是被保护的，但是如果没有考虑到这一层因素的话，会发生什么呢？自然是会产生竞争并引发超乎设想以外的情况发生，以一个用户态程序的代码为例子：
```
int count = 0;
void *IncreaseCount(void *args) 
{
    count += 1;
    printf("count1 = %d\n", count);
    printf("count2 = %d\n", count);
}
int main(int argc, char *argv[])
{
    pthread_t p;
    printf("start:\n");
    for ( int i = 0; i < 10; i ++ ) {
        pthread_create(&p, NULL, IncreaseCount, NULL);
    }
    sleep(30);
    return 0;
}
```
一个很简单的逻辑，但是其输出却比不如我所想：
| 理想 | 现实 |
| --- | --- |
| start:<br>count1 = 1<br>count2 = 1<br>count1 = 2<br>count2 = 2<br>count1 = 3<br>count2 = 3<br>count1 = 4<br>count2 = 4<br>count1 = 5<br>count2 = 5<br>count1 = 6<br>count2 = 6<br>count1 = 7<br>count2 = 7<br>count1 = 8<br>count2 = 8<br>count1 = 9<br>count2 = 9<br>count1 = 10<br>count2 = 10 | start:<br>count1 = 1<br>count2 = 1<br>count1 = 2<br>count2 = 3<br>count1 = 3<br>count1 = 4<br>count2 = 4<br>count2 = 4<br>count1 = 5<br>count2 = 5<br>count1 = 6<br>count2 = 6<br>count1 = 7<br>count2 = 8<br>count1 = 8<br>count2 = 9<br>count1 = 9<br>count2 = 9<br>count1 = 10<br>count2 = 10 |
并且真实的输出并非一定，但是可以清晰的看到`count2 = 2`消失了，可以这样理解，就是当前一个线程的`count2`去取`count`的值的时候，正好被另外线程的`count += 1`给刷成了新的数字，可以通过加入`sleep`来放大这种影响：
```
    printf("count1 = %d\n", count);
    sleep(2);
    printf("count2 = %d\n", count);
```
这样执行后就能发现所有的`count2 = 10`，这是因为当`count2`去访问`count`的时候已经被最后一个线程的`count += 1`刷成了`10`。
简单来说就是一个`临界资源`在程序逻辑执行间隙中间倘若被恶意篡改的话，那篡改者就很有可能对程序造成影响甚至是完成恶意利用，这个换个形容就是`Double Fetch`，那转换到`kernel`中的话这个`double fetch`情况会如何呢？


# `Kernel Double Fetch`
在正常情况下，`内核态`去处理`用户态`程序的数据时候往往是用的类似于`copy_from_user`将数据拷贝到`内核缓冲区`中，后续使用到的数据都是这部分数据，因为处于`内核态`因此基本没有什么风险，但是存在特殊情况在于当要处理的数据十分的动态或者复杂的时候，程序逻辑往往会采用引用指针的方式在内核态直接去访问到用户态的数据，那当出现`double fetch`漏洞的时候就会对整个内核产生影响。例如造成数据越界，缓冲区溢出等各种问题。当然还有情况是内核本身的逻辑会多次从用户态取数据，并且中间存在可利用的间隙，这也是一种`Double Fetch`情况。


![a5529456-7fbe-49d5-8cad-d70e651dbd74.png](DoubleFetch_files/a5529456-7fbe-49d5-8cad-d70e651dbd74.png)


> 这个情况其实非常的少，因为现代内核往往是开启了`SMAP/SMEP`来防止内核访问或执行内核态的数据和代码


依旧是照例子找出曾经出现过的例子来作`demo` -- `CVE-2016-6516`，为了这个我自己还重装了一个`4.5.1`的内核。
这个漏洞出现在`ioctl()`系统调用里，换算到代码上来说就从`fs/ioctl.c#L579`的地方说起
```
    if (get_user(count, &argp->dest_count)) {
        ret = -EFAULT;
        goto out;
    }
```
利用`get_user()`将用户空间中`dest_count`的值赋值到内核空间的`count`，这个值接下来被用作设置`成员指示器`以便计算偏移
```
size = offsetof(struct file_dedupe_range __user, info[count]);  //计算info[count]在file_dedupe_range __user里面的偏移量
```
分配`size`大小的内核内存并从用户空间拷贝`size`大小的数据
```
same = memdup_user(argp, size);
```
而接下来的函的取值对象则是这个`same`的内存区域
```
ret = vfs_dedupe_file_range(file, same);
```
进入到`vfs_dedupe_file_range`中可以直接看到`dest_count`再一次被取值并用作后续使用当中
```
u16 count = same->dest_count;
```
这儿就出现了一个问题，就是`count`的来源第一次来源于`用户内存`，而第二次则来源于拷贝自`用户内存`的`内核内存`中，程序设计的本意在于这两个值虽然取的地方不同但是应该完全相同，然而问题在于`用户内存`在相当程度上来说都是可控的，即倘若在调用`memdup_user`以前就针篡改了`dest_count`的值的话会造成什么影响呢？
> 问题需要一个一个地解决掉


## 如何进入到漏洞代码里
上面的代码是`ioctl_file_dedepe_range()`函数的逻辑，其主要功能在于合并映射多个文件中相同的部分来节省物理内存，其对应的实际功能是`ioctl_fideduperange`，简单来说就是多个文件共享一份数据。
```
       #include <sys/ioctl.h>
       #include <linux/fs.h>
       int ioctl(int src_fd, FIDEDUPERANGE, struct file_dedupe_range *arg);
```
`src_fd`是源文件，而`file_dedupe_range`则代表了要共享的数据
```
           struct file_dedupe_range {
               __u64 src_offset;
               __u64 src_length;
               __u16 dest_count;
               __u16 reserved1;
               __u32 reserved2;
               struct file_dedupe_range_info info[0];
           };
```
其中的`dest_count`就是漏洞的利用点也是用户可控的位置


##  执行空隙
逻辑中并没有类似`cond_resched`这种退让函数，因此在`用户态`下利用只能强插入，采用竞争的方式修改掉这部分数据，原理就是在相同的进程下启动两个线程，一个负责正常的逻辑调用另一个则负责篡改数据，而成功的关键在于篡改数据的时机正好落在`race`里。而这点可以利用`flag`预先设置两个线程的启动时间，然后再篡改线程中加入时间控制，一点点延缓执行时间直到落入`race`。
给个demo，通过双向循环等待来控制两个线程的执行：
```
int finish = 0;
int main_flag = 0;
int exp_flag = 0;
int time = 0;
void exp_thread()
{
    while(!flinsh) {
        exp_flag = 1;
        while(!main_flag) {};
        usleep(time);
        time ++;
        ......
        exp_flag = 0;
    }
}
void main() 
{
    pthread_create(p1, NULL, exp_thread, NULL);
    for ( i = 0; i < try; i ++) {
        while(!exp_flag) {}
        main_flag = 1;
        ......
        main_flag = 0;
    }
    finish = 1;
    pthread_join(p1, NULL);
    return;
}
```


# 参考资料
* [kernel_Double_Fetch详解]([https://blog.csdn.net/qq_43116977/article/details/105868792](https://blog.csdn.net/qq_43116977/article/details/105868792))
* [Double Fetch]([https://ctf-wiki.github.io/ctf-wiki/pwn/linux/kernel/double-fetch-zh/](https://ctf-wiki.github.io/ctf-wiki/pwn/linux/kernel/double-fetch-zh/))
* [以CVE-2016-6516为例深入分析内核Double Fetch型漏洞利用方法]([https://www.freebuf.com/articles/system/156485.html](https://www.freebuf.com/articles/system/156485.html))
* [Linux Kernel API]([https://www.cnblogs.com/pengdonglin137/p/6840624.html](https://www.cnblogs.com/pengdonglin137/p/6840624.html))
* [ioctl_fideduperange(2) — Linux manual page]([https://man7.org/linux/man-pages/man2/ioctl_fideduperange.2.html](https://man7.org/linux/man-pages/man2/ioctl_fideduperange.2.html))