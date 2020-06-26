#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <string.h>
#include<stdlib.h>
int main()
{
  char a[1024] = {0};
  scanf("%s",a);
  printf(a);
  return 0;
}
