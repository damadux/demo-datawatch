#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <dlfcn.h>
#include <inttypes.h>
#include <sys/types.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/resource.h>
#include "dwhooks.h"

#define X86_TBMASK 0xFFFF000000000000

const uintptr_t DW_MASK = ~(65535ULL << 48);

void print_result_msg(int errnum, int nbytes)
{
	switch (errnum)
	{
		case 0:
			printf("Success. Number of bytes written is %d.\n", nbytes);
			break;
		case EINTR:
			printf("The system call was interrupted.\n");
			break;
		case EIO:
			printf("Low-level HW R/W error.\n");
			break;
		case EBADF:
			printf("File descriptor is not valid or READ_ONLY file\n");
			break;
		case EACCES:
			printf("No write permission\n");
			break;
		case EFAULT:
			printf("The address specified in the function is an invalid address.\n");
			break;
		case EINVAL:
			printf("Invalid argument(s).\n");
			break;
		case EFBIG:
			printf("File size to large.\n");
			break;
		case ENOSPC:
			printf("No space available.\n");
			break;
		case EPIPE:
			printf("Broken pipe.\n");
			break;
	        default:
			printf("Unknown error\n");
	}
}
 
void print_pointer(uintptr_t addr, const char *msg) {

	uintptr_t i = (1ULL << (sizeof(addr)*8-1));
	int j = 16;

	printf("%20s: %20p  Binary: ", msg, (int *)addr);
	for(; i; i >>= 1) {
		if (j == 0) printf(" :: "); // as seperator between 16 MSB and 48 LSB
		printf("%d",(addr & i)!=0);
		j--;
	}

	printf("\n");
}


/* Insert the tag into the 16 MSB of the pointer*/
uintptr_t taint(uintptr_t p, uint16_t tag_data) 
{
  p = (uintptr_t)(((uintptr_t)p & DW_MASK) | ((uintptr_t)tag_data << 48));

  return(p);
}

/* Remove the tag from the 16 MSB of the pointer*/
uintptr_t untaint(uintptr_t p) 
{
	p = (void *)(((intptr_t)p << 16) >> 16);

  return(p);
}

int main(int argc, char* argv[])
{
  int errnum;

  if(argc < 2) {
  	printf("%s %s\n",argv[0], "number_of_writes");
	exit(1);
  }

  if(argv[0] < 1){
        printf("Number of writes must be greater than 0");
  }

  struct timeval st, et,st1,et1;

  gettimeofday(&st,NULL);
  struct rusage *usage;
  for (int i=0;i<200;i++){

  	int *ptr = malloc(245);
	//int res = getrusage(RUSAGE_SELF, usage);
	//printf("data: %ld, stack: %ld",usage->ru_idrss,usage->ru_isrss);
	*ptr = 20;
	*ptr = 45;
	free(ptr);
  }

  gettimeofday(&et,NULL);
  int elapsed1 = ((et.tv_sec - st.tv_sec) * 1000000) + (et.tv_usec - st.tv_usec);
  printf("done1");

  dw_init();

  gettimeofday(&st1,NULL);

  for (int i=0;i<200;i++){

  	int *ptr = malloc(245);
	//int res = getrusage(RUSAGE_SELF, usage);
	//printf("data: %lu, stack: %lu",usage->ru_idrss,usage->ru_isrss);
	*ptr = 20;
	*ptr = 45;
	free(ptr);
	
  }
  
  gettimeofday(&et1,NULL);
  int elapsed2 = ((et1.tv_sec - st1.tv_sec) * 1000000) + (et1.tv_usec - st1.tv_usec);
  printf("Time elapsed1: %d micro seconds \n", elapsed1);
  printf("Time elapsed2: %d micro seconds \n", elapsed2);
  
}
