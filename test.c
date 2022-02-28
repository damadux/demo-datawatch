#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <dlfcn.h>
#include "dwhooks-clean.h"




int main(int argc, char* argv[]) {

   dw_init();
   int *m3 = malloc(16*sizeof(int));
   *m3 = 20;
   printf("address2:%p\n",m3);
   printf("value:%i\n",*m3);
   //m3 = realloc(m3,32*sizeof(int));
   
   free(m3);
   printf("PID:%ld",(long)getpid());
   
}
