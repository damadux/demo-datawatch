#define _GNU_SOURCE

#include <malloc.h>
#include <string.h>
#include <signal.h>
#include <stdlib.h>
#include <pthread.h>
#include <ucontext.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#include <execinfo.h>

#include <execinfo.h>
#include <unistd.h>

typedef __uint64_t uint64_t;
#define MAX_MALLOCS 0xFF0
#define START_MALLOC 0x0000
#define DW_TAG 0xC0000000000000
#define OFFSET 0x10000000000000
#define max(a,b) \
   ({ __typeof__ (a) _a = (a); \
       __typeof__ (b) _b = (b); \
     _a > _b ? _a : _b; })
/* Prototypes for our hooks */
static void *dw_malloc_hook(size_t, const void *);
static void dw_free_hook(void *, const void *);
static void *dw_realloc_hook(void *, size_t, const void *);

/* Variables to save original hooks */
static void *(*old_malloc_hook)(size_t, const void *);
static void *(*old_free_hook)(void *, const void *);
static void *(*old_realloc_hook)(void*, size_t, const void *);
// where we store the allocated size
static size_t *sizes;
static void* *original_address;
static void* *return_address;

static volatile long dw_TAG; // A constant tag to store in the top 16 bits of any new pointer
static volatile uintptr_t dw_MASK;


static struct object_id {
    int status;
    long baseAddr;
    size_t length;
}object_id;

static volatile struct object_id malloc_metadata[256];

int head = -1;
int tail = -1;



// keeps track of where we are in the array
static volatile int count, all_count, free_count;

static void sigsegv_handler(int sig, siginfo_t *si, void *ptr)
{
    ucontext_t *uc = (ucontext_t *)ptr;
    
    /* Get the address at the time the signal was raised */
    printf("SIGSEGV for Address: 0x%lx",(long) uc->uc_mcontext.gregs[REG_RAX]);
    printf(" for instruction:0x%lx\n",(long) uc->uc_mcontext.gregs[REG_RIP]);
    
    
    // Untaint address  

    long addr = (long) uc->uc_mcontext.gregs[REG_RAX];
    

    if((addr & (long) (dw_TAG << 48)) != 0) {
	// Bounds checking
        long taint = (addr & 0xFFFF000000000000) / 0x1000000000000;
	    printf("%lu\n", taint);
        long base_addr = malloc_metadata[taint].baseAddr;
        int obj_size = malloc_metadata[taint].length;
        long org_addr = (long) ((uc->uc_mcontext.gregs[REG_RAX] << 16 ) >> 16 );
        printf("%lu\n", base_addr);
        printf("%u\n", obj_size);
        printf("%lu\n", org_addr);
        if (base_addr <= org_addr && (base_addr + obj_size) >= org_addr){
            // Bounds check succeeded, nothing to do

            //Untaint address
            long org_addr = (long) ((uc->uc_mcontext.gregs[REG_RAX] << 16 ) >> 16 );
            uc->uc_mcontext.gregs[REG_RAX] = org_addr;
        }
        else {
            printf("Bounds check unsuccessful, exit for now\n");
            // Bounds check unsuccessful, exit for now
            exit(-1);
        }
    }
    else {
    printf("Not a tainted address\n");
    exit(-1);
    }
    
}



extern void
dw_init(void)
{
    printf("1");
    sizes = (size_t*) malloc(sizeof(size_t) * MAX_MALLOCS);
    original_address = (void**) malloc(sizeof(void *) * MAX_MALLOCS);
    return_address = (void**) malloc(sizeof(void *) * MAX_MALLOCS);

    //init metadata
    for(int i=0;i<256;i++){
        malloc_metadata[i].status = 1;
        if (i == 255) {
            malloc_metadata[i].baseAddr = -1;
        }
        else {
            malloc_metadata[i].baseAddr = i+2;
        }
       
        malloc_metadata[i].length = 0;
    }
    head = 1;
    tail = 255;
    //struct object_id malloc_metadata[256];

    old_malloc_hook = __malloc_hook;
    old_free_hook = __free_hook;
    old_realloc_hook = __realloc_hook;
    __malloc_hook = dw_malloc_hook;
    __free_hook = dw_free_hook;
    __realloc_hook = dw_realloc_hook;
   
    struct sigaction sa;

    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    sa.sa_sigaction = sigsegv_handler;
    sigaction(SIGSEGV, &sa, NULL);
    
}

static void *
dw_malloc_hook(size_t size, const void *caller)
{
    void *result;

    /* Restore all old hooks */
    __malloc_hook = old_malloc_hook;
    __free_hook = old_free_hook;
    __realloc_hook = old_realloc_hook;

    /* Call recursively */
    result = malloc(size);
   
    /* Encode the object metadata */
    if (head == -1){
        //TODO: enlarge list
        return -1;
    }
    malloc_metadata[head].status = 0;
    int next_head = malloc_metadata[head-1].baseAddr;
    malloc_metadata[head].baseAddr = (long) result;
    malloc_metadata[head].length = size;

    printf("Object_id: %u \n", head);
    printf("BaseAddr: %p \n", result);
    printf("Length: %zu \n", size);

    result = (void *)(((uintptr_t)result) | ((uintptr_t)head << 48));    

    if (head == tail){
        // Increase size, if possible
        head = -1;
        tail = -1;
    }
    else {
        head = next_head;
    }
    
    unsigned long return_addr = (unsigned long)__builtin_return_address(0);
   
    count++;
    /* Save underlying hooks */
    old_malloc_hook = __malloc_hook;
    old_free_hook = __free_hook;
    old_realloc_hook = __realloc_hook;

    /* Restore our own hooks */
    __malloc_hook = dw_malloc_hook;
    __free_hook = dw_free_hook;
    __realloc_hook = dw_realloc_hook;

    return result;
}

static void
dw_free_hook (void *ptr, const void *caller)
{
    /* Restore all old hooks */
    __malloc_hook = old_malloc_hook;
    __free_hook = old_free_hook;
    __realloc_hook = old_realloc_hook;

    long addr = (long) ptr;
    printf("%lu\n",addr);

    long taint = ((long)ptr & 0xFFFF000000000000) / 0x1000000000000;
    long index = taint-1;
    
    if (malloc_metadata[index].status == 0){
        malloc_metadata[index].status = 1;
        malloc_metadata[tail].baseAddr = taint;
        malloc_metadata[index].baseAddr = -1;
        malloc_metadata[index].length = 0;
        tail = index;
    }
    else {
        return -1;
    }
    if (head == -1) {
        head = index;
    }
      

    //  Untaint
    ptr = (void *)(((intptr_t) ptr << 16) >> 16);
     
    /* Call recursively */
    free (ptr);

    /* Save underlying hooks */
    old_malloc_hook = __malloc_hook;
    old_free_hook = __free_hook;
    old_realloc_hook = __realloc_hook;

    /* Restore our own hooks */
    __malloc_hook = dw_malloc_hook;
    __free_hook = dw_free_hook;
    __realloc_hook = dw_realloc_hook;
}

static void*
dw_realloc_hook (void *ptr, size_t size,const void *caller)
{
    /* Restore all old hooks */
    __malloc_hook = old_malloc_hook;
    __free_hook = old_free_hook;
    __realloc_hook = old_realloc_hook;


    long taint = ((long)ptr & 0xFFFF000000000000) / 0x1000000000000;

    if (malloc_metadata[taint].status == 0){
        long addr = malloc_metadata[taint].baseAddr;

        /* Call recursively with untainted address*/
        int result = realloc((void *)addr,size);
        malloc_metadata[taint].baseAddr = result;
        malloc_metadata[taint].length = size;
        
    }
    
    
    

    /* Save underlying hooks */
    old_malloc_hook = __malloc_hook;
    old_free_hook = __free_hook;
    old_realloc_hook = __realloc_hook;

    /* Restore our own hooks */
    __malloc_hook = dw_malloc_hook;
    __free_hook = dw_free_hook;
    __realloc_hook = dw_realloc_hook;

    return result;
}

