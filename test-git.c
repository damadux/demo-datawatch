#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <dlfcn.h>
#include <inttypes.h>
#include <sys/types.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>

#include "dwhooks.h"

#define X86_TBMASK 0xFFFF000000000000



int main(int argc, char* argv[])
{
  int errnum;

  if(argc < 2) {
  	printf("%s %s\n",argv[0], "sleep_time");
	exit(1);
  }


	printf("PID:%ld -- sleep time %d\n",(long)getpid(), atoi(argv[1]));
  sleep(atoi(argv[1]));
/*
  clock_t begin = clock();

  int status1 = execl("/home/david/Documents/Clement-Benchmark/uftrace-benchmark/applications/source/git-2.35.3/git", "status", NULL);
  int status = system("gcc -L . -Wall -Wextra -g -o test-malloc test.c -ldw");

  clock_t end = clock();
  double time_spent = (double)(end - begin) / CLOCKS_PER_SEC;
  printf("%f\n",time_spent);
*/
  dw_init();
  clock_t begin1 = clock();

  int status2 = execl("/home/david/Documents/Clement-Benchmark/uftrace-benchmark/applications/source/git-2.35.3/git", "status", NULL);
  int status = system("gcc -L . -Wall -Wextra -g -o test-malloc test.c -ldw");  

  clock_t end1 = clock();
  double time_spent = (double)(end1 - begin1) / CLOCKS_PER_SEC;
  printf("%f\n",time_spent);
  printf("PID:%ld\n",(long)getpid());
}
