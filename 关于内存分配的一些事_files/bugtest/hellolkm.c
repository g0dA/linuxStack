/*==============================================================================

# Author:       lang  lyi4ng@gmail.com
# Filetype:     C source code
# Environment:  Linux & Archlinux
# Tool:         Vim & Gcc
# Date:         2019.09.17
# Descprition:  Randomly written code

================================================================================*/
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/delay.h>
#include <linux/errno.h>
#include <linux/thread_info.h>
#include <linux/slab.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/string.h>
#include <linux/uaccess.h>

MODULE_LICENSE("GPL");

int hello_major;
struct class *hello_class;
struct cdev cdev;

struct hellolkm_struct {
	char *hello_char;
	long length;
};

struct hellolkm_struct hellolkm;
//open
int hellolkm_open(struct inode *inode, struct file *filp) 
{	
	printk("hellolkm open\n");
	return 0;
}

//kfree
int hellolkm_release(struct inode *inode, struct file *filp)
{
	kfree(hellolkm.hello_char);
	printk("hellolkm close, kfree : %p\n", hellolkm.hello_char);
	return 0;
}

//read
ssize_t hellolkm_read(struct file *filp, char *buffer, size_t length, loff_t *offset)
{
	ssize_t result = 0;

	if (!hellolkm.hello_char)
		return -1;

	if (hellolkm.length <= 0)
		return -1;

	if (hellolkm.length < length)
		length = hellolkm.length;
	
	copy_to_user(buffer, hellolkm.hello_char, length);		
	
	return 0;
}

//write
ssize_t hellolkm_write(struct file *filp, const char *buffer, size_t length, loff_t *offset)
{
	ssize_t result = 0;
	
	if (!hellolkm.hello_char)
		return -1;

	if (hellolkm.length < length)
		return -1;

	copy_from_user(hellolkm.hello_char, buffer, length);	
	return result;
}

//kmalloc
long hellolkm_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	int result = 0;

	switch (cmd) {
		//按照需求申请内存
		case 666:
			if (arg > 0) {
				hellolkm.hello_char = (char *)kmalloc(arg, GFP_KERNEL);
				memset(hellolkm.hello_char, 0, arg);
				hellolkm.length = arg;
				printk("kmalloc(%d) : %p\n", arg, hellolkm.hello_char);
			} else
				result = -1;
			break;
		//释放内存
		case 999:
			kfree(hellolkm.hello_char);
			printk("kfree : %p\n", hellolkm.hello_char);
			break;
		default:
			result = -1;
			break;
	}	
	
	return result;
}

static const struct file_operations hello_fops = {
	.owner = THIS_MODULE,
	.read = hellolkm_read,
	.write = hellolkm_write,
	.open = hellolkm_open,
	.release = hellolkm_release,
	.unlocked_ioctl = hellolkm_ioctl, 
};

int __init hellolkm_init(void)
{
	dev_t devno;
	int result;
	
	//alloc dev_no for dev hello	
	result = alloc_chrdev_region(&devno, 0, 1, "hello");
	hello_major = MAJOR(devno);

	printk("hello_major /dev/hello: %d\n", hello_major);

	if (result < 0)
		return result;

	//init cdev
	cdev_init(&cdev, &hello_fops);
	cdev.owner = THIS_MODULE;

	//add dev to system
	result = cdev_add(&cdev, devno, 1);

	if (result < 0)
		return result;

	//create class of dev
	hello_class = class_create(THIS_MODULE, "hello");
	
	
	if (!hello_class) {
		printk("create hello_class fail");
		cdev_del(&cdev);
		return 0;
	}

	//add dev to fs
	device_create(hello_class, NULL, devno, NULL, "hello");


	printk("hello init success\n");
	return 0;

}

void __exit hellolkm_exit(void)
{
	cdev_del(&cdev);
	device_destroy(hello_class, MKDEV(hello_major, 0));	
	class_destroy(hello_class);
	unregister_chrdev_region(MKDEV(hello_major, 0), 1);
	printk("hellolkm exit success\n");
	return;
}

module_init(hellolkm_init);
module_exit(hellolkm_exit);
