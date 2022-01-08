/*==============================================================================

# Author:       lang  lyi4ng@gmail.com
# Filetype:     C source code
# Environment:  Linux & Archlinux
# Tool:         Vim & Gcc
# Date:         2019.09.17
# Descprition:  Randomly written code

================================================================================*/

#include <stdio.h>
#include <stdint.h>
#include <x86intrin.h>
#include <linux/types.h>


int main()
{
	unsigned long min, max, value;
	min = 0x1;
	max = 0x1;

	__u64 chi = min ^ max, delta;
	__u8 bits = 0;

	delta = (1ULL << bits) - 1;
	
	value = min & ~delta;
	printf("value = %llx, off = %llx\n", value, delta);

	__u64 v, mu;

	__u64 value64, ma64;
	value64 = 0x0;
	ma64 = 0xffffffffffffffff;

	value64 &= (1ULL << 32) - 1;
	ma64 &= (1ULL << 32) - 1;
	printf("subreg: value64 = %llx, off64 = %llx\n", value64, ma64);


	v = value64 | value;
	mu = delta & ma64;

	printf("real var_off: var = %llx, off = %llx\n", v & ~mu, mu);

}
