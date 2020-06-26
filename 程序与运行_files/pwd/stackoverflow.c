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
#include <string.h>

int main(int argc, char *argv[])
{

	char str[10];


	gets(str); //定义字符数组并赋值

	char buffer[10]; //开辟 10 个字节的局部空间

	strcpy(buffer,str);

	int rete;
	rete = strcmp(buffer, "key");

	if ( rete >0 ){
		printf("key");
	}

	return 0;
}

