# Kernel漏洞挖掘日记
## 2020.11.25
`bpf_prog_create_from_user at net/core/filter.c:1396`

> Double Fetch

```
copy_form_user(fprog, user_filter)

user_filter=0x55a51610b090

fprog=0xffff8800692afe48

gef➤  p *fprog
$45 = {
  len = 0x7,
  filter = 0x55a51610b930 //用户态地址
}

gef➤  p *fprog->filter
$49 = {
  code = 0x20,
  jt = 0x0,
  jf = 0x0,
  k = 0x4
}

fsize = (fprog->len * sizeof(fprog->filter[0])) //0x38

if (copy_from_user(fp->insns, fprog->filter, fsize)) //二次copy, fprog->filter可通过用户态控制
```
因为调用的`copy_from_user`无法在第二个参数上做手脚导致内核`Oops`
> 有个同类型的函数`bpf_prog_create`中调用的`memcpy(fp->insns, fprog->filter, fsize);`但是已经出现上报的案例：[KASAN: slab-out-of-bounds Read in bpf_prog_create](https://lkml.org/lkml/2019/12/5/7)

