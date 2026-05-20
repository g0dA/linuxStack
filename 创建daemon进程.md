> 本次学习来源于一个需求

先整理下需求场景：
```
一个进程在执行完一段函数A产生一个结果a后，a会传入下一个函数B，此函数B用作开启一个socket然后把a传输出去，等传输完成socket关闭后，继续执行函数C，且B函数与C函数没有任何关联
```
一个线性执行方式，但是问题就出来了，就是如果`B函数`的网络传输不能快速完成，那么整个程序的执行就必然会有等待，因此现在做的事情就是将`B函数`做一个异步处理。

因此想法就是是否能够做到`A函数`在执行后产生一个独立进程用来执行`B函数`，当网络传输结束后则自动关闭掉。

调研了一圈，`daemon`进程就出来了。

## `daemon`进程
> 核心实现在于独立出一个`进程会话`，也就是调用`setsid()`。由于会话对控制终端的独占性，进程同时与控制终端脱离。

1. 通过`fork`创建一个子进程出来
2. 结束父进程，过继到`init`进程之下
3. 调用`setsid`创建新的进程会话，且自身成为新进程组的领头进程。
4. 关闭从父进程继承的非必要`fd`
5. 切换工作目录到根目录，防止从父进程继承来的目录是挂载在一个文件系统的，不切换根目录的话会导致不允许`umount`
6. 清除继承的`umask`，防止创建文件时权限出现问题

```c
/*==============================================================================

# Author: lang lyi4ng@gmail.com
# Filetype: C source code
# Environment: Linux & Archlinux
# Tool: Vim & Gcc
# Date: 2019.09.17
# Descprition: Randomly written code

================================================================================*/

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/types.h>
#include <unistd.h>
#include <signal.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <time.h>
#include <stdlib.h>

int init_daemon(void) 
{ 
 int pid; 
 int i; 
 
 //忽略终端I/O信号，STOP信号
 signal(SIGTTOU,SIG_IGN);
 signal(SIGTTIN,SIG_IGN);
 signal(SIGTSTP,SIG_IGN);
 signal(SIGHUP,SIG_IGN);
	
 pid = fork();
 if(pid > 0) {
  exit(0); //结束父进程，使得子进程成为后台进程
 }
 else if(pid < 0) { 
  return -1;
 }
 
 //建立一个新的进程组,在这个新的进程组中,子进程成为这个进程组的首进程,以使该进程脱离所有终端
 setsid();
 
 //再次新建一个子进程，退出父进程，保证该进程不是进程组长，同时让该进程无法再打开一个新的终端
 pid=fork();
 if( pid > 0) {
  exit(0);
 }
 else if( pid< 0) {
  return -1;
 }
 
 //关闭所有从父进程继承的不再需要的文件描述符
 for(i=0;i< NOFILE;close(i++));
 
 //改变工作目录，使得进程不与任何文件系统联系
 chdir("/");
 
 //将文件当时创建屏蔽字设置为0
 umask(0);
 
 //忽略SIGCHLD信号
 signal(SIGCHLD,SIG_IGN); 

 sleep(8); 
 exit(0);
 //return 0;
}

int main()
{
    pid_t child;
    long orig_rax;
    child = fork();
    if(child == 0)
    {
        printf("i am child\n");
     init_daemon();
    }
    return 0;
}
```





