/*==============================================================================

# Author:       lang  lyi4ng@gmail.com
# Filetype:     C source code
# Environment:  Linux & Archlinux
# Tool:         Vim & Gcc
# Date:         2019.09.17
# Descprition:  Randomly written code

================================================================================*/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define SIZE    1
#define VMSIZE    4096*5
char *addrs[SIZE];
char *dest[VMSIZE][SIZE];
int main()
{
        int i;
	printf("step 1\n");
        for (i = 0; i < SIZE; i++) {
                memset(dest[i], 1, 4096);
        }	
	getchar();
        // step 2:使用malloc分配一个page的内存
        printf("step 2\n");
        for (i = 0; i < SIZE; i++) {
		addrs[i] = malloc(VMSIZE);
	}
        getchar();
        // step 3:只读malloc分配出来的内存
        printf("step 3\n");
        for (i = 0; i < SIZE; i++) {
		memcpy(dest[i], addrs[i], VMSIZE);
	}
       getchar();
}

