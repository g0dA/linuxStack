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
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[])
{

	char *p1;
	p1 = (char *)malloc(sizeof(char) * 10);
	memcpy(p1, "hello", 10);
	printf("before free: p1 address = %p\n", p1);
	free(p1);
//	char *p2;
//	p2 = (char *)malloc(sizeof(char) * 10);
//	memcpy(p1, "world", 10);
	printf("after free: p1 address = %p\n", p1);
	return 0;

}

