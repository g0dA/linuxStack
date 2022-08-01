static int proc_exe_link(struct dentry *dentry, struct path *exe_path)
{
	struct task_struct *task;
	struct file *exe_file;

	task = get_proc_task(d_inode(dentry));
	if (!task)
		return -ENOENT;
	exe_file = get_task_exe_file(task);
	put_task_struct(task);
	if (exe_file) {
		*exe_path = exe_file->f_path;
		path_get(&exe_file->f_path);
		fput(exe_file);
		return 0;
	} else
		return -ENOENT;
}

/proc/self/exe会从当前task->mm->exe_file，并从其中提取到exe_path的相关内容，其中无视mnt_namespace的影响

打开/proc/self/exe的调用栈
[#0] 0xffffffff812c56c0 → proc_exe_link(dentry=0xffff88800785c3c0, exe_path=0xffffc90000147e50)
[#1] 0xffffffff812c766b → proc_pid_readlink(dentry=0xffff88800785c3c0, buffer=0x7ffda6e1d1a0 <error: Cannot access memory at address 0x7ffda6e1d1a0>, buflen=0x1000)
[#2] 0xffffffff8124a9c8 → vfs_readlink(dentry=0xffff88800785c3c0, buffer=0x7ffda6e1d1a0 <error: Cannot access memory at address 0x7ffda6e1d1a0>, buflen=0x1000)
[#3] 0xffffffff8123cc8f → do_readlinkat(dfd=0xffffff9c, pathname=0x497703 "/proc/self/exe", buf=0x7ffda6e1d1a0 <error: Cannot access memory at address 0x7ffda6e1d1a0>, bufsiz=0x1000)
[#4] 0xffffffff8123cd05 → __do_sys_readlink(bufsiz=<optimized out>, buf=<optimized out>, path=<optimized out>)
[#5] 0xffffffff8123cd05 → __se_sys_readlink(bufsiz=<optimized out>, buf=<optimized out>, path=<optimized out>)
[#6] 0xffffffff8123cd05 → __x64_sys_readlink(regs=<optimized out>)
[#7] 0xffffffff81c249ab → do_syscall_x64(nr=<optimized out>, regs=0xffffc90000147f58)
[#8] 0xffffffff81c249ab → do_syscall_64(regs=0xffffc90000147f58, nr=<optimized out>)
[#9] 0xffffffff81e0007c → entry_SYSCALL_64()


