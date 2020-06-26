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

int main(int argc, char *argv[])
{

	int n = 0;
	int a = 0;

	printf("01234%n56789%n\n", &n, &a);
	printf("n = %d, a = %d", n, a);
	return 0;

}

