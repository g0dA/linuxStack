# NC模拟

> nc -lvvp 9999

此刻`0`，`1`，`2`对应还是`/dev/pts/2`，这是一个文件，所以程序可以通过`read(0,buf,sizeof(buf))`标准输入存入到`buf`中

因此在执行`nc -lvvp 9999 0</dev/null`时，无法获取到任何数据，因为没有标准输入
> nc 127.0.0.1 9999 1>123.txt 0</dev/null

当执行了如上后，产生通信，而监听端输入`whoami`，`123.txt`被写入了`whoami`

## 顺序

`监听端获取键盘输入存入buf(fgets())` --> `读取buf数据写入向sockfd(write())`==`输出到屏幕` --> `连接端从sockfd中读取信息存到buf(read())` --> `把缓冲区的数据写到指定的fd(write)`

> 其中网络I/O的操作有多组，
* read()/write() 
* recv()/send() 
* readv()/writev() 
* recvmsg()/sendmsg() 
* recvfrom()/sendto()

## 问题

无法单纯的依靠程序打开文件的特征，来判断数据是否被传输到了远端。因为无法确认，键盘的输入是否被写入了`sockfd`中，检测方式可以考虑观察进程的系统调用，但是代价略大，尤其是对于即时进程来说，就是在分析一个系统调用日志，这样的数据处理量值得商榷。

# 参考

* [LInux C API参考手册](https://www.kancloud.cn/wizardforcel/linux-c-api-ref/)

* [linux 下的 C socket 编程](http://cighao.com/2016/07/12/c-linux-socket/)
