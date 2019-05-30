#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/idr.h>
#include <asm/unistd.h>
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

asmlinkage long (*old_sys_getdents)(unsigned int fd,
				struct linux_dirent __user *dirent,
				unsigned int count);

//idtr
static struct _idtr
{
        unsigned short limit;
        unsigned long base;
}__attribute__ ((packed));

//idt_table struct
struct _gate_struct {
	u16		offset_low;
	u16		segment;
	struct idt_bits	bits;
	u16		offset_middle;
#ifdef CONFIG_X86_64
	u32		offset_high;
	u32		reserved;
#endif
} __attribute__((packed));


unsigned char *system_table;

unsigned char *system_call;

unsigned char *do_int80_syscall_32;


int __init hack_kernel(void){
	int i=0;
	unsigned int vc=0;
	unsigned char buf[4]={0};
	struct _idtr idtr;
	struct _gate_struct *system_call_idt;
	int k=0;
	set_addr_rw();
	asm("sidt %0":"=m"(idtr));
	
	//中断向量地址的获取,idtr.base是基地址
	printk("[address]idt_table=0x%lx\n",idtr.base);
	

	system_call_idt=idtr.base+16*0x80;
	system_call =(long)(system_call_idt->offset_high <<32)|(long)(system_call_idt->offset_middle<<16|system_call_idt->offset_low);
	printk("[address]system_call=0x%lx\n",system_call);
	for(i;i<128;i++){
		if((system_call[0]&0x000000ff)==0xe8){
			k++;
			buf[0]=system_call[1];
			buf[1]=system_call[2];
			buf[2]=system_call[3];
			buf[3]=system_call[4];
			if(k==2){
				printk("[memory]e8 %lx %lx %lx %lx\n",buf[0],buf[1],buf[2],buf[3]);
				do_int80_syscall_32 = (int)system_call+*(int *)buf+5;
				printk("[address]do_int80_syscall_32=0x%lx\n",do_int80_syscall_32);
				break;
			}	
			
		}
		system_call++;
	
	}
	
	for(i;i<256;i++){
		buf[0]=do_int80_syscall_32[1];
		buf[1]=do_int80_syscall_32[2];
		buf[2]=do_int80_syscall_32[3];
		buf[3]=do_int80_syscall_32[4];
		if((do_int80_syscall_32[0]&0x000000ff)==0xe8){
			printk("[memory]e8 %lx %lx %lx %lx\n",buf[0],buf[1],buf[2],buf[3]);
			printk("[address]call=0xffffffff%lx\n",(int)do_int80_syscall_32+*(int *)buf+5);
			do_int80_syscall_32 = do_int80_syscall_32-1;
			printk("[memory]%lx %lx %lx %lx %lx\n",do_int80_syscall_32[0],do_int80_syscall_32[1],do_int80_syscall_32[2],do_int80_syscall_32[3],do_int80_syscall_32[4]);
			break;		
						
		}

/*
			
			printk("[memory]%lx %lx %lx %lx %lx\n",do_int80_syscall_32[0],buf[0],buf[1],buf[2],buf[3]);
*/

			
		do_int80_syscall_32++;
	
	}
	set_addr_ro();


	return 0;
}


void __exit hack_kernel_exit(void){
	

	set_addr_rw();
	
	set_addr_ro();
	return 0;
}
module_init(hack_kernel);
module_exit(hack_kernel_exit)
