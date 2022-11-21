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
#include <capstone/capstone.h>
#include <bfd.h>

#include <execinfo.h>
#include <unistd.h>

typedef __uint64_t uint64_t;
#define MALLOC_METADATA_MIN_SIZE 256
#define MALLOC_METADATA_MAX_SIZE 65000


#define MAX_MALLOCS 0xFF0
#define START_MALLOC 0x0000
#define DW_TAG 0xC0000000000000
#define OFFSET 0x10000000000000
#define OPERANDS_SIZE 8
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
    long baseAddr;
    long length;
    long status;
}object_id;

static volatile struct object_id * malloc_metadata;

int head = -1;
int tail = -1;


extern void
__attribute__((constructor)) dw_init()
{
    int malloc_metadata_size = 356;
	printf("2\n");
    
    if ((malloc_metadata_size < MALLOC_METADATA_MIN_SIZE) || (malloc_metadata_size > MALLOC_METADATA_MAX_SIZE)) {
        printf("Invalid malloc metadata table size");
        exit(-1);
    }
    
    //init metadata

    malloc_metadata = malloc(sizeof(object_id) * malloc_metadata_size);
    int *malloc_addr = malloc_metadata;
    
    //raise(SIGSEGV);
    /**
	bfd *abfd;
	asymbol *new;
	asymbol *ptrs[2];
	
	abfd = bfd_openw("tex.bfd",NULL);
	new = bfd_make_empty_symbol(abfd);
    new->name = "dummy_symbol";
    //new->section = bfd_make_section_old_way(abfd, ".text");
    new->flags = BSF_GLOBAL;
    new->value = malloc_metadata;
    
    ptrs[0] = new;
    ptrs[1] = (asymbol *)0;

    bfd_set_symtab(abfd, ptrs, 1);
    bfd_close(abfd);
	*/
	
    for(int i=0;i<malloc_metadata_size;i++){
        malloc_metadata[i].status = 1;
        if (i == malloc_metadata_size - 1) {
            malloc_metadata[i].baseAddr = -1;
        }
        else {
            malloc_metadata[i].baseAddr = i+2;
        }
       
        malloc_metadata[i].length = 0;
    }
    head = 1;
    tail = malloc_metadata_size - 1;

    old_malloc_hook = __malloc_hook;
    old_free_hook = __free_hook;
    old_realloc_hook = __realloc_hook;
    __malloc_hook = dw_malloc_hook;
    __free_hook = dw_free_hook;
    __realloc_hook = dw_realloc_hook;
    
    
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
    malloc_metadata[head-1].status = 0;
    int next_head = malloc_metadata[head-1].baseAddr;
    malloc_metadata[head-1].baseAddr = (long) result;
    malloc_metadata[head-1].length = size;

    //printf("Object_id: %u \n", head);
    //printf("BaseAddr: %p \n", result);
    //printf("Length: %zu \n", size);

    result = (void *)(((uintptr_t)result) | ((uintptr_t)head << 48));    

    if (head == tail){
        // Increase size, if possible
        head = -1;
        tail = -1;
    }
    else {
        head = next_head;
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

static void
dw_free_hook (void *ptr, const void *caller)
{
    /* Restore all old hooks */
    __malloc_hook = old_malloc_hook;
    __free_hook = old_free_hook;
    __realloc_hook = old_realloc_hook;

    long addr = (long) ptr;
    //printf("Address freed: %lu\n",addr);

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
    void *result;
    
    //printf("realloc");
    /* Restore all old hooks */
    __malloc_hook = old_malloc_hook;
    __free_hook = old_free_hook;
    __realloc_hook = old_realloc_hook;


    long taint = ((long)ptr & 0xFFFF000000000000) / 0x1000000000000;

    if (malloc_metadata[taint - 1].status == 0){
        long addr = malloc_metadata[taint - 1].baseAddr;

        /* Call recursively with untainted address*/
        result = realloc((void *)addr,size);
        malloc_metadata[taint - 1].baseAddr = result;
        malloc_metadata[taint - 1].length = size;
        
    }

    else {
        result = realloc(ptr,size);
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

