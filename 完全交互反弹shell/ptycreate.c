#include<stdio.h>
#define _XOPEN_SOURCE
#include<stdlib.h>
#include<unistd.h>
#include<sys/types.h>
#include<sys/stat.h>
#include<fcntl.h>
#include<sys/ioctl.h>
#define DATASIZE 100

int grantpt (int fd);

int unlockpt (int fd);

char *ptsname (int __fd);

char *argv[];

char buf[DATASIZE];  //创建缓冲区，这里只需要大小为1字节
int main()
{
    //创建master、slave对并解锁slave字符设备文件
    int mfd = open("/dev/ptmx", O_RDWR);
    grantpt(mfd);
    unlockpt(mfd);
    //查询并在控制台打印slave文件位置
    fprintf(stderr,"%s\n",ptsname(mfd));
    
    int bash_pid = fork();
    if(bash_pid ==0){
        int pts_fd = open(ptsname(mfd), O_RDWR);
        dup2(pts_fd,0);
        dup2(pts_fd,1);
        dup2(pts_fd,2);
        close(mfd);
        execv("/bin/bash", argv);
    }

    int pid=fork();//分为两个进程
    if(pid)//父进程从master读字节，并写入标准输出中
    {
        while(1)
        {
            if(read(mfd,buf,1)>0)
                write(1,buf,1);
            else
                sleep(1);
        }
    }
    else//子进程从标准输入读字节，并写入master中
    {
        while(1)
        {
            if(read(0,buf,1)>0)
                write(mfd,buf,1);
            else
                sleep(1);
        }
    }

    return 0;
}