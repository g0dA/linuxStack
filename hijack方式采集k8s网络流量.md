# 背景
主要是为了以后的信息审计和溯源，所以要针对容器服务的网络流量做采集还要求得关联到`pod`，只能看好几天环境了。


# 调研
`pod`这是一个`k8s`的概念与系统层本身是无关的，然而如果要做网络采集的话就以现代来说`ebpf`无疑是一个非常好的技术方案，但是这个就更远离`pod`这一概念了，静下心来思考一下我们所诉说的容器在linux上来说其实本质上就是一种`namespace`的隔离，只要某个进程满足了`namespace`的隔离那么就可以说是在容器中，而网络连接的发起在用户态下则是必然来自于某个进程，因此就可以得到这么一条信息链：
```
socket -> task -> namespace -> contaienr -> pod
```
## `socket`
这个其实比较简单，`ebpf`本身有大把的方式能够实现，毕竟其出身就是为了处理掉网络相关的问题，我这边是只关注了`egress`流量，因此只需要针对主动发起的`socket`作一个监控即可，然后为了轻量最终选择了`kprobe`的方式来`hook`了出口逻辑中的某一个函数(细节方面就不多说了)。


## `task` AND `namespace`
同样由`ebpf`实现，只需要在触发的时候获取到当前`cpu`上的`task_struct`即可，不作过多赘述。而`namespace`就是有点意思了，不过鉴于`ebpf`本身想要流畅的使用就需要用到高达`4.15`以上的内核版本，因此在这个基础上完全从`nsproxy`里面读取想要的数值即可。


## 题外话
在到获取到`namespace`的时候我当时冒出一个想法，就是按照`k8s`的逻辑来说最终生成的`pod`的`uts`应该会被设置成为`podname`的值，那么只需要获取到`uts namespace`中的`name`即可直接将`task`和`pod`关联上，当然常规情况下也确实是如此但是当遇见了`hostNetwork: true`的情况的时候就不一样了。
```
func modifyHostNetworkOptionForContainer(hostNetwork bool, sandboxID string, hc *dockercontainer.HostConfig) {
 sandboxNSMode := fmt.Sprintf("container:%v", sandboxID)
 hc.NetworkMode = dockercontainer.NetworkMode(sandboxNSMode)
 hc.IpcMode = dockercontainer.IpcMode(sandboxNSMode)
 hc.UTSMode = ""


 if hostNetwork {
  hc.UTSMode = namespaceModeHost
 }
}
```
在`kubelet`的逻辑中，当检测到容器的`network mode`为`host`时候会一并将`UTSMode`刷成主机的`uts namespace`，这就导致当遇到这种情况下的容器时无法获取到`pod name`这一值。


## `container` AND `pod`
如何从`namespace`关联到`container`才是重点，这儿所说的`container`是指在`k8s`环境下由`container runtime`创建出来的容器，在常规的情况下是`docker`，而`pod`则又是`k8s`的概念与`docker`本身无关，从`docker`上获取到`pod`的信息仔细想想的话应该只有元数据中才会有，而这个数据可以通过`docker inspect`的方式拿到。
```
{
    Config: 
    {
        Labels:
        {
            ......
            "io.kubernetes.pod.name": "test-pod-name",
            ......
        }
    }
}
```
如果是这样的话针对`docker event`的`watch`其实是一个很常规的方案，但是这样就又引入了一个应用层的依赖因此不做考虑，那么去探求`inspect`的底层逻辑的话实质上还是一个文件读取与输出，而读取的文件就是`/var/lib/docker/containers/containerID/config.v2.json`，这是一个固定路径其实也不是，准确的说是得看`/etc/docker/daemon.json`的配置关于`docker`数据(`images`, `volumes`, `cluster state`)的存储目录的配置，默认的是`/var/lib/docker`当然可以通过设置`data-root`来修改
> graph has been deprecated in v17.05.0 .You can use data-root instead.


`docker`中针对`container`的唯一识别只有一个`containerID`，那么从一个`task`中获取到这个`containerID`就是成了一个需求，这个很幸运的从`docker`本身的一个特性能够获取到，那就是`docker`会为容器创建一个`cgroup`目录，而这个目录名在`k8s`环境下则正是`containerID`，那么从`task`的角度来说`task`的`cgroup name`就是`containerID`
> 参考下面的实际数据来说，这是一个`/kubepods/Qos/pod<uid>/<containerID>`的结构，其中`/kubepods/Qos/pod<uid>/`是由`kubelet`创建在`task`中属于一个`parent cgroup`，而`Qos`类型则是`kubelet`根据`pod`的配置抉择出来


```
> cat /proc/self/cgroup
11:cpuset:/kubepods/burstable/pod35b82523-06c1-48e7-9e61-2521a89b703b/b5fa49123b796b99fe605af0f8d019f3b3a8cb445b529b892e0d3788682469af
10:devices:/kubepods/burstable/pod35b82523-06c1-48e7-9e61-2521a89b703b/b5fa49123b796b99fe605af0f8d019f3b3a8cb445b529b892e0d3788682469af
9:hugetlb:/kubepods/burstable/pod35b82523-06c1-48e7-9e61-2521a89b703b/b5fa49123b796b99fe605af0f8d019f3b3a8cb445b529b892e0d3788682469af
8:perf_event:/kubepods/burstable/pod35b82523-06c1-48e7-9e61-2521a89b703b/b5fa49123b796b99fe605af0f8d019f3b3a8cb445b529b892e0d3788682469af
7:blkio:/kubepods/burstable/pod35b82523-06c1-48e7-9e61-2521a89b703b/b5fa49123b796b99fe605af0f8d019f3b3a8cb445b529b892e0d3788682469af
6:memory:/kubepods/burstable/pod35b82523-06c1-48e7-9e61-2521a89b703b/b5fa49123b796b99fe605af0f8d019f3b3a8cb445b529b892e0d3788682469af
5:freezer:/kubepods/burstable/pod35b82523-06c1-48e7-9e61-2521a89b703b/b5fa49123b796b99fe605af0f8d019f3b3a8cb445b529b892e0d3788682469af
4:net_cls,net_prio:/kubepods/burstable/pod35b82523-06c1-48e7-9e61-2521a89b703b/b5fa49123b796b99fe605af0f8d019f3b3a8cb445b529b892e0d3788682469af
3:pids:/kubepods/burstable/pod35b82523-06c1-48e7-9e61-2521a89b703b/b5fa49123b796b99fe605af0f8d019f3b3a8cb445b529b892e0d3788682469af
2:cpu,cpuacct:/kubepods/burstable/pod35b82523-06c1-48e7-9e61-2521a89b703b/b5fa49123b796b99fe605af0f8d019f3b3a8cb445b529b892e0d3788682469af
1:name=systemd:/kubepods/burstable/pod35b82523-06c1-48e7-9e61-2521a89b703b/b5fa49123b796b99fe605af0f8d019f3b3a8cb445b529b892e0d3788682469af
0::/
```
# 后记
其实方案上不难，但是中途遇到了许许多多的`ebpf`坑点，这着实让我对`ebpf`这门技术产生了极大的兴趣并开始坚信这玩意真的有一天会吞噬这个世界，因此后面准备着手去探究一下`ebpf`的相关技术了。


# 参考资料
* [attempt to change docker data-root fails - why](https://stackoverflow.com/questions/55344896/attempt-to-change-docker-data-root-fails-why)
* [ebpf code skill](http://chenlingpeng.github.io/2020/08/13/ebpf-code-skill/)
* [配置 Pod 的服务质量](https://kubernetes.io/zh/docs/tasks/configure-pod-container/quality-service-pod/)
* [走进docker(07)：docker start命令背后发生了什么？](https://segmentfault.com/a/1190000010057763)
* [how to get the container id in pod? #50309](https://github.com/kubernetes/kubernetes/issues/50309)