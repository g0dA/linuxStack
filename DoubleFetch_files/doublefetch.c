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
#include <pthread.h>


int count = 0;

void *IncreaseCount(void *args) 
{
	count += 1;
	printf("count1 = %d\n", count);
	sleep(2);
	printf("count2 = %d\n", count);
}


int main(int argc, char *argv[])
{
	pthread_t p;
	printf("start:\n");
	for ( int i = 0; i < 10; i ++ ) {
		pthread_create(&p, NULL, IncreaseCount, NULL);
	}
	sleep(30);
	return 0;

}

