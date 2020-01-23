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

#define STACK_SIZE (1024*1024) /* Stack size for cloned child */

int parent_uid;
int parent_gid;

static char child_stack[STACK_SIZE];

//[...]
void set_uid_map(pid_t pid, int inside_id, int outside_id, int length) {
    char path[256];
    sprintf(path, "/proc/%d/uid_map", pid);
    FILE* uid_map = fopen(path, "w");
    fprintf(uid_map, "%d %d %d", inside_id, outside_id, length);
    fclose(uid_map);
}
void set_gid_map(pid_t pid, int inside_id, int outside_id, int length) {
	/* 3.19之后需要先修改/proc/PID/setgroups
	 * 将内容从allow修改为deny
	 * 否则无法修改gid_map的内容
	 * */
    
    char path2[256];
    sprintf(path2,"/proc/%d/setgroups",pid);
    FILE* setgroups = fopen(path2,"w");
    fprintf(setgroups, "deny");
    fclose(setgroups);

    char path[256];
    sprintf(path, "/proc/%d/gid_map", pid);
    FILE* gid_map = fopen(path, "w");
    fprintf(gid_map, "%d %d %d", inside_id, outside_id, length);
    fclose(gid_map);
}
int child_main(){
	printf("进入子进程:%d\n",getpid());

	cap_t caps;
	set_uid_map(getpid(), 0, parent_uid, 1);
   	set_gid_map(getpid(), 0, parent_gid, 1);
	//caps = cap_get_proc();
	//printf("capabilities: %s\n",cap_to_text(caps,NULL));
	char *arg[] = {"/bin/bash",NULL};
	char *newhostname = "UTSnamespace";
	//sethostname(newhostname,sizeof(newhostname));

	execv("/bin/bash",arg);
	
	return 1;
}


int main(void){

	printf("创建子进程\n");
	parent_uid = getuid();
	parent_gid = getgid();

	int child_pid = clone(child_main,child_stack+STACK_SIZE,CLONE_NEWUSER | CLONE_NEWIPC | CLONE_NEWCGROUP | CLONE_NEWNET | CLONE_NEWNS | CLONE_NEWUTS | SIGCHLD,NULL);
	

	waitpid(child_pid,NULL,0);
	printf("退出子进程\n");

	return 0;

}

