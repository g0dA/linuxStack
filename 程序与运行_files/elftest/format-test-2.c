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

int main()
{

  unsigned long long b = 0;
  printf("aaaa%30c%2147483614c%1$ln\n", &b);
  printf("b = %ld\n", b);
  return 0;
}
