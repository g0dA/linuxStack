#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/reg.h>   /* For constants  ORIG_RAX etc */
#include <stdio.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include <string.h>
#include <stdlib.h>
#include <linux/limits.h>

void read_argument(pid_t child, char *reg)
{
    char *child_addr;
    int i;
  
    //读取RDI寄存器的值，是一个地址
    child_addr = (char *)ptrace(PTRACE_PEEKUSER, child, 8*RDI, NULL);
 
    do {
        long val;
        char *p;
  	//每次只读取一个字节
        val = ptrace(PTRACE_PEEKTEXT, child, child_addr, NULL);
        if (val == -1) {
        	return;
	}
        child_addr += sizeof (long);
  
        p = (char *) &val;
        for (i = 0; i < sizeof (long); ++i, ++reg) {
            *reg = *p++;
            if (*reg == '\0') break;
        }
    } while (i == sizeof (long));
}
   
void put_argument(pid_t child,char *com){

	char *reg_addr,*com_addr;
	reg_addr = (char*)ptrace(PTRACE_PEEKUSER,child,8*RSP,0);
	reg_addr -=128+PATH_MAX;
	com_addr = reg_addr;

	do{
		int i;
		char val[sizeof(long)];
		for(i=0;i<sizeof(long);++i,++com){
			val[i] = *com;
			if(*com == '\0') break;
		}
		ptrace(PTRACE_POKETEXT,child,reg_addr,*(long *)val);
		reg_addr+=sizeof(long);
	}while(*com);

	ptrace(PTRACE_POKEUSER,child,8*RDI,com_addr);
	
}
int main()
{
    pid_t child;
    long orig_rax;
    child = fork();
    int status;
    char *newcom="/usr/bin/who";
    //寄存器中的command
    char command[PATH_MAX];
    if(child == 0)
    {
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
	execl("./ppp", "ppp","test", NULL);
    }
    else
    {
	while(1){
        
	wait(&status);
	if(WIFEXITED(status)){
		break;
	}
	//读取寄存器的内容，ORIG_RAX值为系统调用号
	orig_rax = ptrace(PTRACE_PEEKUSER,
                          child, 8 * ORIG_RAX,
                          NULL);

	printf("[SYSTEM CALL IS %ld]\n",orig_rax);
        if(orig_rax == SYS_execve){
		//目前只读取RDI寄存器的传参
		read_argument(child,command);
		if(strcmp("/usr/bin/whoami",command)==0){
			printf("ok\n");
			put_argument(child,newcom);
		}		
	}

        ptrace(PTRACE_SYSCALL,child,NULL,NULL);
    }
    }
    return 0;
}
