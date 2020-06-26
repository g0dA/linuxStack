> 记录一下工作中遇到的一个坑点


事情是这样的，因为我修改了线上所有的`bash`，就导致各种shell脚本遇到了问题都会找到我这儿，然后今天就遇到一个情况，我的同事写了大概这样一个脚本
```
#!/bin/bash
pid=
function handle_exit {
 sleep 10
 if [ x"${pid}" != x ]
 then
  echo "kill -15 ${pid}"
  kill -15 ${pid}
 fi
}
trap handle_exit INT TERM QUIT
./server.sh &
pid=$!
wait ${pid} 
exit_code=$?
echo "exit with code ${exit_code}"
exit ${exit_code}
```
然后他的需求是获得`server.sh`退出时的返回码。
代码看起来合情合理，然而问题就来了，在实际使用的时候，子进程还没有退出呢，父进程就直接退出了，我测了几下，直觉上是`wait ${pid}`根本没有生效，但是又没有弄懂为什么。


首先是关于`trap`，这个指令的执行很有意思，我本以为只要脚本接收到信号，就会里面转入到`trap`的逻辑之中，事实上大多数文章也是这么教导的，无论当前的执行状态是什么，只要一个`ctrl+c`就可以看到`trap`中的逻辑执行，这不明显是信号来了就执行吗？


然而事实却并非如此，写一个这样的脚本：
```
#!/bin/bash
function _exit {
 echo "exit with trap"
}
trap _exit INT TERM QUIT
sleep 25
```
然后通过`ps xf -o pid,ppid,args`找到这个脚本的`PID`，接着通过`kill -15 PID`来结束这个进程，可以清晰的发现一直等`sleep 25`执行完了才会进入到`_exit`的逻辑中，而`ctrl+c`出现的现象其实是因为`ctrl+c`本身是向整个进程组发送`SIGINT`信号，而`sleep`是属于当前进程组的，因此也会接收到此信号从而直接退出。


说白了，结论就是`trap`会等待当前命令结束以后再去处理结束队列中的信号。


那上面的问题就很有意思了，进程当前状态是一个`wait`状态，因此直接发送`kill -15`的话会导致这个`wait`直接退出，然后才是去执行`trap`中的逻辑退出`子进程`，再加上`子进程`是`后台进程`，自然就出现了`父进程`先退出，且无法获取返回码的情况。


那么实际上只要让`trap`之后再执行一次`wait`就好了，第一个`wait`会被退出，那第二个`wait`就会在`trap`后执行，因此应该这么改一下脚本：
```
#!/bin/bash
pid=
function handle_exit {
 sleep 10
 if [ x"${pid}" != x ]
 then
  echo "kill -15 ${pid}"
  kill -15 ${pid}
 fi
}
trap handle_exit INT TERM QUIT
./server.sh &
pid=$!
wait ${pid} 
trap - INT TERM QUIT
wait ${pid}
exit_code=$?
echo "exit with code ${exit_code}"
exit ${exit_code}
```
# 参考资料
* [How to propagate SIGTERM to a child process in a Bash script](http://veithen.io/2014/11/16/sigterm-propagation.html)
* [关于Linux Shell的信号trap功能你必须知道的细节](https://blog.robotshell.org/2012/necessary-details-about-signal-trap-in-shell/)