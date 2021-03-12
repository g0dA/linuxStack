/*==============================================================================

# Author:       lang  lyi4ng@gmail.com
# Filetype:     C source code
# Environment:  Linux & Archlinux
# Tool:         Vim & Gcc
# Date:         2019.09.17
# Descprition:  namespace learning

================================================================================*/

#define _GNU_SOURCE
#include <sched.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/capability.h>
#include <sys/mount.h>
#include <sys/syscall.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <limits.h>

#define STACK_SIZE (1024*1024) /* Stack size for cloned child */
#define errExit(msg)    do { perror(msg); exit(EXIT_FAILURE); \
                               } while (0)

int parent_uid;
int parent_gid;
char *rootfs = "/home/lang/Desktop/newrootfs";

 static int
pivot_root(const char *new_root, const char *put_old)
{
	return syscall(SYS_pivot_root, new_root, put_old);
}

static char child_stack[STACK_SIZE];

int child_main(){

	printf("进入子进程:%d\n",getpid());

	if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) == -1)
		errExit("mount-MS_PRIVATE");
	
	if (mount(rootfs, rootfs, NULL, MS_BIND | MS_REC | MS_PRIVATE, NULL) == -1)
		errExit("mount-MS_BIND");

	if (chdir(rootfs) == -1)
		errExit("chdir1");

	if (pivot_root(".", ".") == -1)
		errExit("pivot_root");

	if (umount2(".", MNT_DETACH) == -1)
		perror("umount2");

	if (chdir("/") == -1)
		perror("chdir2");


	if (mount("proc", "/proc", "proc", 0, NULL) == -1)
		errExit("mount-proc");

	char *arg[] = {"/bin/bash", NULL};

	execv("/bin/bash", arg);
	
	return 1;
}


int main(void){

	printf("创建子进程\n");
	parent_uid = getuid();
	parent_gid = getgid();

	int child_pid = clone(child_main, child_stack + STACK_SIZE, CLONE_NEWNS | CLONE_NEWPID | SIGCHLD, NULL);
	

	waitpid(child_pid, NULL, 0);
	printf("退出子进程\n");

	return 0;

}

