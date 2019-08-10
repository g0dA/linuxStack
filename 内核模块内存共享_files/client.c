#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <linux/fb.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <errno.h>

#define PAGE_SIZE 4096

int main(int argc , char *argv[])
{
        int fd;
        int i;
        unsigned char *p_map;

        //打开设备
        fd = open("/dev/mymap",O_RDWR);
        if(fd < 0) {
                printf("open fail\n");
                exit(1);
        }

        //内存映射
        p_map = (unsigned char *)mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        if(p_map == (void *)-1) {
                printf("mmap fail\n");
                goto here;
        }

        close(fd);
        //打印映射后的内存中的前10个字节内容,
        //并将前10个字节中的内容都加上10，写入内存中
        //通过cat cat /sys/devices/virtual/misc/mymap/rng_current查看内存是否被修改      
		printf("%s\n",p_map);

here:
        munmap(p_map, PAGE_SIZE);
        return 0;
}
