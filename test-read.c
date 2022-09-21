#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <dlfcn.h>
#include <inttypes.h>
#include <sys/types.h>
#include <errno.h>
#include <fcntl.h>

#include "dwhooks.h"

#define X86_TBMASK 0xFFFF000000000000

const uintptr_t DW_MASK = ~(65535ULL << 48);

void print_result_msg(int errnum, int nbytes)
{
	switch (errnum)
	{
		case 0:
			printf("Success. Number of bytes read is %d.\n", nbytes);
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
  	printf("%s %s\n",argv[0], "sleep_time");
	exit(1);
  }


	printf("PID:%ld -- sleep time %d\n",(long)getpid(), atoi(argv[1]));
  sleep(atoi(argv[1]));
  dw_init(356);

  int *ptr = malloc(sizeof(int));
  // ptr pointer was tagged in the malloc hook.


	uint16_t tag_data = 12345; // This is the tag to store in the top 16 bits 
  print_pointer(ptr, "After Malloc:");
  ptr = untaint(ptr);
  print_pointer(ptr, "After untaint:");

  // Access is authorized as the address is untainted
  *ptr = 20;
  


  // File descriptor
  int fd = open("/home/david/Documents/datawatch/textfile.txt",O_RDONLY);
  /* 
   * Pass an ordinary (untaintedi) pointer to the write system call
   * SUCCESS
   */
  printf("\n 1. Read from the untainted pointer \n");
  printf("The value of ptr is : %p\n", ptr);
  //int nW = write(1, ptr, sizeof(int));
  int nR = read(fd,ptr, sizeof(int));
  errnum = errno;
  print_result_msg(errnum, nR);

  
  //if (((uintptr_t)ptr & X86_TBMASK) != 0) {
  //  printf("The address is tagged ? %p \n", ((uintptr_t)ptr & X86_TBMASK));
  //} else
  //  printf("The address is not tagged 0x%lx \n", ((uintptr_t)ptr & X86_TBMASK));


  ptr =  taint(ptr, tag_data);

  //if (((uintptr_t)ptr & X86_TBMASK) != 0)
  //  printf("The address is tagged %p \n", ((uintptr_t)ptr & X86_TBMASK));
  //else
  //  printf("The address is not tagged 0x%lx \n", ((uintptr_t)ptr & X86_TBMASK));

  /* 
   * Pass a tainted pointer to the write system call
   * FAIL
   */
  printf("\n 2. Read from the tainted pointer \n");
  printf("The value of ptr is : %p\n", ptr);
  //nW = write(1, ptr, sizeof(int));
  nR = read(fd,ptr, sizeof(int));
  errnum = errno;
  print_result_msg(errnum, nR);


  // Access will generate a SIGSEGV as the address is tainted.
  printf("\n 3. Access to the tainted pointer \n");
  *ptr = 20;

  free(ptr);

  printf("PID:%ld\n",(long)getpid());
}
