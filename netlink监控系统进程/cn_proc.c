#include <sys/types.h>
#include <sys/socket.h>
#include <signal.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <linux/netlink.h>
#include <linux/connector.h>
#include <stdio.h>
#define _LINUX_TIME_H
#include <unistd.h>
#include <linux/cn_proc.h>

#define MAX_MSGSIZE 256
#ifndef SOL_NETLINK
#define SOL_NETLINK 270
#endif

int sd;
struct sockaddr_nl l_local, daddr;
int on;
int len;
struct nlmsghdr *nlhdr = NULL;
struct msghdr msg;
struct iovec iov;
int * connector_mode;
struct cn_msg * cnmsg;
struct proc_event * procevent;
int counter = 0;
int ret;
struct sigaction sigint_action;

//发送控制器指令
void change_cn_proc_mode(int mode)
{
	      memset(nlhdr, 0, sizeof(NLMSG_SPACE(MAX_MSGSIZE)));
	      memset(&iov, 0, sizeof(struct iovec));
	      memset(&msg, 0, sizeof(struct msghdr));
        cnmsg = (struct cn_msg *)NLMSG_DATA(nlhdr);
        connector_mode = (int *)cnmsg->data;
        * connector_mode = mode;

        nlhdr->nlmsg_len = NLMSG_LENGTH(sizeof(struct cn_msg) + sizeof(enum proc_cn_mcast_op));
        nlhdr->nlmsg_pid = getpid();
        nlhdr->nlmsg_flags = 0;
        nlhdr->nlmsg_type = NLMSG_DONE;
        nlhdr->nlmsg_seq = 0;

        cnmsg->id.idx = CN_IDX_PROC;
        cnmsg->id.val = CN_VAL_PROC;
        cnmsg->seq = 0;
        cnmsg->ack = 0;
        cnmsg->len = sizeof(enum proc_cn_mcast_op);

        iov.iov_base = (void *)nlhdr;
        iov.iov_len = nlhdr->nlmsg_len;
        msg.msg_name = (void *)&daddr;
        msg.msg_namelen = sizeof(daddr);
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        ret = sendmsg(sd, &msg, 0);
        if (ret == -1) {
        	perror("sendmsg error:");
		exit(-1);
        }
}

//信号控制函数，关闭接收器
void sigint_handler(int signo)
{
	change_cn_proc_mode(PROC_CN_MCAST_IGNORE);
	printf("process event: turn off process event listening.\n");
	close(sd);
	exit(0);
}

//文件读取函数
void *file_get_content(char *filename){

    FILE *fp = NULL;

    if(!(fp = fopen(filename, "rb")))
    {
        printf("fopen failed!");
        exit(0);
    }

    int content_len = 1024;
    char *content = (char *)malloc(content_len);
    if(!content)
    {
        printf("malloc failed\n");
        exit(0);
    }
    memset((void*)content, 0, content_len);

    int nRead = 0;
    nRead = fread(content, 1, content_len - 1, fp);

    int i;
    for(i=0;i<nRead;i++)
    {
        if(content[i]==0) content[i] = ' ';
    }

    fclose(fp);

    return content;

}


/*********************************************
 * 根据PID获取到相关信息
 *
 * /proc/[pid]/cmdline是一个只读文件，包含进程的完整命令行信息
 * /proc/[pid]/cwd是进程当前工作目录的符号链接。
 * /proc/[pid]/exe为实际运行程序的符号链接
 *********************************************/

//读取exe链接信息
void *exename(int pid){
    char path[256] ={0};
    sprintf (path, "/proc/%d/exe",pid);

    char buff[257];
    readlink (path, buff, 257);
    char *path_name =(char *)malloc (strlen(buff));
    memset (path_name,0, strlen(buff));
    memcpy (path_name, buff,strlen (buff));

    return path_name;
}

//读取cwd链接信息
void *cwdname(int pid){
    char path[256] ={0};
    sprintf (path, "/proc/%d/cwd",pid);
    char buff[257];
    readlink (path, buff, 257);
    char *path_name =(char *)malloc (strlen(buff));
    memset (path_name,0, strlen(buff));
    memcpy (path_name, buff,strlen (buff));

    return path_name;
}

//读取进程命令信息函数
void *cmdline(int pid){
  char filename[1024]={0};
  char *content;
  size_t len;

  //cmdline：进程完整命令信息
  if(!sprintf (filename,"/proc/%d/cmdline",pid)){
    perror ("[error]sprintf:");
    return NULL;
  }

  if((content = file_get_content(filename))!=NULL){
      return content;
  }


  return NULL;

}

//主函数
int main(void)
{

	memset(&sigint_action, 0, sizeof(struct sigaction));
	sigint_action.sa_flags = SA_ONESHOT;
	sigint_action.sa_handler = &sigint_handler;
	sigaction(SIGINT, &sigint_action, NULL);
	nlhdr = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_MSGSIZE));
	if (nlhdr == NULL) {
		perror("malloc:");
		exit(-1);
	}


  daddr.nl_family = AF_NETLINK;
  daddr.nl_pid = 0;
  daddr.nl_groups = CN_IDX_PROC;

	sd = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_CONNECTOR);

	l_local.nl_family = AF_NETLINK;
	l_local.nl_groups = CN_IDX_PROC;
	l_local.nl_pid = getpid();

	if (bind(sd, (struct sockaddr *)&l_local, sizeof(struct sockaddr_nl)) == -1) {
        	perror("bind");
	        close(sd);
        	return -1;
	}

	change_cn_proc_mode(PROC_CN_MCAST_LISTEN);
	printf("process event: turn on process event listening.\n");

	while (1) {
		memset(nlhdr, 0, NLMSG_SPACE(MAX_MSGSIZE));
		memset(&iov, 0, sizeof(struct iovec));
		memset(&msg, 0, sizeof(struct msghdr));

                iov.iov_base = (void *)nlhdr;
                iov.iov_len = NLMSG_SPACE(MAX_MSGSIZE);
                msg.msg_name = (void *)&daddr;
                msg.msg_namelen = sizeof(daddr);
                msg.msg_iov = &iov;
                msg.msg_iovlen = 1;

                ret = recvmsg(sd, &msg, 0);
                if (ret == 0) {
                        printf("Exit.\n");
                        exit(0);
                }
                else if (ret == -1) {
                        perror("recvmsg:");
                        exit(1);
                }
		else {
			cnmsg = (struct cn_msg *)NLMSG_DATA(nlhdr);
			procevent = (struct proc_event *)cnmsg->data;
      /*
     * From the user's point of view, the process
     * ID is the thread group ID and thread ID is the internal
     * kernel "pid". So, fields are assigned as follow:
     *
     *  In user space     -  In  kernel space
     *
     * parent process ID  =  parent->tgid
     * parent thread  ID  =  parent->pid
     * child  process ID  =  child->tgid
     * child  thread  ID  =  child->pid
     */

			switch (procevent->what) {
				case PROC_EVENT_NONE:
					printf("process event: acknowledge for turning on process event listening\n\n\n");
					break;
                		case PROC_EVENT_FORK:
					printf("process event: fork\n");
					printf("parent pid:%d\nexe->%s\ncwd->%s\nCommand:%s\nchild pid:%d\nexe->%s\ncwd->%s\nCommand:%s\n\n\n",
                       //procevent->event_data.fork.parent_pid,
                       procevent->event_data.fork.parent_tgid,
                       exename (procevent->event_data.fork.parent_tgid),
                       cwdname (procevent->event_data.fork.parent_tgid),
                       cmdline (procevent->event_data.fork.parent_tgid),
                       //procevent->event_data.fork.child_pid,
                       procevent->event_data.fork.child_tgid,
                       exename (procevent->event_data.fork.child_tgid),
                       cwdname (procevent->event_data.fork.child_tgid),
                       cmdline (procevent->event_data.fork.child_tgid));
					break;
                		case PROC_EVENT_EXEC:
					printf("process event: exec\n");
					printf("pid:%d\nexe->%s\ncwd->%s\nCommand:%s\n\n\n",
                       //procevent->event_data.exec.process_pid,
                       procevent->event_data.exec.process_tgid,
                       exename (procevent->event_data.exec.process_tgid),
                       cwdname (procevent->event_data.exec.process_tgid),
                       cmdline (procevent->event_data.exec.process_tgid));
					break;
                		/*case PROC_EVENT_UID:
					printf("process event: uid\n");
					printf("process tid:%d, pid:%d, uid:%d->%d\n\n\n",
                       procevent->event_data.id.process_pid,
                       procevent->event_data.id.process_tgid,
                       procevent->event_data.id.r.ruid,
                       procevent->event_data.id.e.euid);
					break;
                		case PROC_EVENT_PTRACE:
					printf("process event: ptrace\n");
					printf("process tid:%d, pid:%d, uid:%d->%d\n\n\n",
                       procevent->event_data.ptrace.process_pid,
                       procevent->event_data.ptrace.process_tgid,
                       procevent->event_data.ptrace.tracer_pid,
                       procevent->event_data.ptrace.tracer_tgid);
					break;
                		case PROC_EVENT_COMM:
					printf("process event: comm\n");
					printf("process tid:%d, pid:%d, comm:%s\n\n\n",
                       procevent->event_data.comm.process_pid,
                       procevent->event_data.comm.process_tgid,
                       procevent->event_data.comm.comm);
					break;
                		case PROC_EVENT_GID:
					printf("process event: gid\n");
					printf("process tid:%d, pid:%d, gid:%d->%d\n\n\n",
                       procevent->event_data.id.process_pid,
                       procevent->event_data.id.process_tgid,
                       procevent->event_data.id.r.rgid,
                       procevent->event_data.id.e.egid);
					break;
                	case PROC_EVENT_EXIT:
					printf("process event: exit\n");
					printf("tid:%d, pid:%d, exit code:%d\n\n\n",
                       procevent->event_data.exit.process_pid,
                       procevent->event_data.exit.process_tgid,
                       procevent->event_data.exit.exit_code);
					break;*/
				default:
        //printf("%d\n", procevent->what);
					//printf("Unkown process action\n\n\n");
					break;
			}
		}
	}
}
