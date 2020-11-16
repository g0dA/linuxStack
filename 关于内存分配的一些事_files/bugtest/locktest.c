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
#include <pthread.h>

static int i = 0;
void thread_A_func(void)
{
	i++;
}

void thread_B_func(void)
{
	i++;
}

int main(int argc, char *argv[])
{

	pthread_t tid1, tid2;
		

	pthread_create(&tid1, NULL, (void *)thread_A_func, NULL);
	pthread_create(&tid2, NULL, (void *)thread_B_func, NULL);

	char *rev = NULL;
	
	pthread_join(tid1, (void *)&rev);
	pthread_join(tid2, (void *)&rev);

	printf("i = %d\n", i);
	return 0;

}

