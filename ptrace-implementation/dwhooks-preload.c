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
extern void *__libc_malloc(size_t size);
extern void *__libc_realloc(void* ptr, size_t size);
extern void __libc_free(void* ptr);

int malloc_hook_active = 0;
int realloc_hook_active = 0;
int free_hook_active = 0;

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


void
send_metadata_addr(int* metadata_addr){

	// Raise a SIGSEGV signal with rax = metadata addr
	
	uint64_t addr_test = metadata_addr;
	__asm__ ("push %%rax\n\t"
		"mov %%rax,%0"
		:
		: "r" (addr_test): "rax");
	raise(SIGSEGV);
	__asm__ ("pop %rax");
	
}

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
    
    send_metadata_addr(malloc_addr);
    
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

    malloc_hook_active = 1;
    realloc_hook_active = 1;
    free_hook_active = 1;
    
    
}

static void *
dw_malloc_hook(size_t size, const void *caller)
{
    void *result;

    /* Deactivate all hooks */
    malloc_hook_active = 0;
    realloc_hook_active = 0;
    free_hook_active = 0;

    /* Call recursively */
    result = __libc_malloc(size);
   
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

    /* Restore our own hooks */
    malloc_hook_active = 1;
    realloc_hook_active = 1;
    free_hook_active = 1;

    return result;
}





static void
dw_free_hook (void *ptr, const void *caller)
{
    /* Restore all old hooks */
    malloc_hook_active = 0;
    realloc_hook_active = 0;
    free_hook_active = 0;

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
    __libc_free(ptr);

    /* Restore our own hooks */
    malloc_hook_active = 1;
    realloc_hook_active = 1;
    free_hook_active = 1;
}

static void*
dw_realloc_hook (void *ptr, size_t size, const void *caller)
{
    void *result;
    
    //printf("realloc");
    /* Restore all old hooks */
    malloc_hook_active = 0;
    realloc_hook_active = 0;
    free_hook_active = 0;


    long taint = ((long)ptr & 0xFFFF000000000000) / 0x1000000000000;

    if (malloc_metadata[taint - 1].status == 0){
        long addr = malloc_metadata[taint - 1].baseAddr;

        /* Call recursively with untainted address*/
        result = realloc((void *)addr,size);
        malloc_metadata[taint - 1].baseAddr = result;
        malloc_metadata[taint - 1].length = size;
        
    }

    else {
        result = __libc_realloc(ptr,size);
    }
    

    /* Restore our own hooks */
    malloc_hook_active = 1;
    realloc_hook_active = 1;
    free_hook_active = 1;

    return result;
}

void*
malloc (size_t size)
{
	void *caller = __builtin_return_address(0);
	if (malloc_hook_active)
		return dw_malloc_hook(size, caller);
	return __libc_malloc(size);
}

void*
realloc (void *ptr, size_t size)
{
	void *caller = __builtin_return_address(0);
	if (realloc_hook_active)
		return dw_realloc_hook(ptr, size, caller);
	return __libc_realloc(ptr, size);
}

void
free (void *ptr)
{
	void *caller = __builtin_return_address(0);
	if (free_hook_active)
		return dw_free_hook(ptr, caller);
	return __libc_free(ptr);
}

