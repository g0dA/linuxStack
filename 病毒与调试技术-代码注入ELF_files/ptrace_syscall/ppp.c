#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/reg.h>   /* For constants  ORIG_RAX etc */
#include <stdio.h>
#include <sys/syscall.h>
#include <sys/user.h>
int main(int argc,char *argv[])
{
    char globale_buf[]="sdsdsdsdsd";
    printf("[Output is %s]\n",argv[1]);
    execl("/usr/bin/ls","ls","-a",NULL);
    return 0;
}



