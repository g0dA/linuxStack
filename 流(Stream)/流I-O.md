> LInux一切皆文件，但是对于文件的操作又有基于文件描述符的I/O和基于流的I/O

`文件描述符`的操作(如`open()`)返回的是一个文件描述符，每个进程空间的PCB中都有一个文件描述符表，打开的文件都通过此表中的描述符引用。
`流(stream)`的操作(如`fopen()`)返回的是FILE结构指针，指向一个FILE结构体，而一个FILE结构体是包含一个缓冲区和一个文件描述符值的，也就是说，这个指针就是一个句柄的句柄。
```
#ifndef _FILE_DEFINED
struct _iobuf {
        char *_ptr; //文件输入的下一个位置
        int _cnt; //当前缓冲区的相对位置
        char *_base; //文件的起始位置
        int _flag; //文件标志
        int _file; //文件的有效性验证
        int _charbuf;//检查缓冲区状况，若无缓冲区则不读取
        int _bufsiz; //文件的大小
        char *_tmpfname;//临时文件名
        };
typedef struct _iobuf FILE;
#define _FILE_DEFINED
#endif /* _FILE_DEFINED */
```
其中`_file`指向`进程级打开文件表`，然后可以通过`进程级表`找到`系统级打开文件表`。
![20131210113655109](https://img-blog.csdn.net/20131210113655109)
1. 文件路径，文件描述符是唯一的。文件指针不是唯一的，但是指向的对象唯一
2. `FILE结构体(FILE*)`中包含`fd`信息，还包含`I/O缓冲`，可以理解成`FILE*`是对`fd`的封装，多应用于`fopen()`，少用于`open()`
> fd -- fdopen() -->FILE*    FILE* -- fileno() -->fd 
fileno(FILE *stream);返回`stream`对应的文件描述符

## 流
一句话，`流(stream)`表示任意输入源或任意输出的目的地，是`文件描述符`的抽象

> 这个知识点主要是为了检测socat的反弹shell学习的，但是后来发现不是这个知识点，而是unix域套接字的东西，所以就此打住，以后再接触吧
