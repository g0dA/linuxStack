## 监控
```
Netlink套接字
```
实时发送新创建的进程信息，DEMO：[proc_event](https://github.com/dbrandt/proc_events/)
```
$ netstat -anop|grep ESTABLISHED
```
> 用户态下获取到的信息

## 定位

[lsof](https://linuxtools-rst.readthedocs.io/zh_CN/latest/tool/lsof.html)

根据逻辑判断是否为`反弹bash`进程
> 用户态下获取到的信息

```
[root@localhost ~]# lsof -p 12324 -R
```
### 如何判断反弹shell
反弹shell的方式
1. shell的反弹
    特征:
    * 文件描述符号0会被重定向到套接字文件
    * 文件描述符号1和2会被重定向到套接字文件
    >[Bash_main_pages](https://blog.csdn.net/longyinyushi/article/details/50730828)
2. Socket反弹
    特征:
    * 产生套接口文件描述符与外界通信
    > POSIX标准要求每次打开文件时（含socket）必须使用当前进程中最小可用的文件描述符号码
    * 会产生SHLL子进程
    >子进程会继承父进程的文件描述符，通过dup2()复制套接口进程
    >文件描述符0的值与套接口文件描述符相同

3. 进程反弹
    特征:
    * 产生进程间管道文件
    * 文件描述符0指向管道
    * 文件描述符号1指向管道
    * 生成一个长时间存在且指向管道的SHELL进程

4. 管道符反弹
    特征:
    * 文件描述符号1指向管道
    * 文件描述符号0和可读可写文件的文件描述符内容同指向套接字文件

## 相关进程
```
ps --ppid ppid
```

## 跟踪
```
execve 信息提取
```
audit进行EXECVE监控
```
auditctl -D
清除当前规则
```
```
auditctl -a always,exit -F arch=b64 -S execve -k rule01_exec_command
```
消息同属于一组日志，来自规则`rule01_exec_command`,类型分别是：`SYSCALL`、`EXECVE`、`CWD`、`PATH`、`PATH`。其中，前三条日志有极高的价值。

*     type=SYSCALL：日志规则“rule01_exec_command”被触发，uid=996的用户，通过父进程ppid=18259，调用/usr/bin/bash，执行了命令sh，进程pid=13545。

*     type=SYSCALL和type=EXECVE都能看到执行的程序名称和参数

*     type=CWD则说明了，命令执行所在的目录cwd="/opt/www/php"


