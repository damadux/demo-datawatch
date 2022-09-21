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

#include <execinfo.h>

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
    int status;
    long baseAddr;
    size_t length;
}object_id;

static volatile struct object_id * malloc_metadata;

int head = -1;
int tail = -1;



static void sigsegv_handler(int sig, siginfo_t *si, void *ptr)
{
    ucontext_t *uc = (ucontext_t *)ptr;
    
    /* Get the address at the time the signal was raised */
    //printf("SIGSEGV for Address: 0x%lx",(long) uc->uc_mcontext.gregs[REG_RAX]);
    //printf(" for instruction:0x%lx\n",(long) uc->uc_mcontext.gregs[REG_RIP]);
    
    
    //printf("1\n");
    
    
    __malloc_hook = old_malloc_hook;
    __free_hook = old_free_hook;
    __realloc_hook = old_realloc_hook;
    
    uint8_t mod_reg = 0;
    csh handle;
    
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK){
        printf("Capstone was unable to open");
        return -1;
    }
    
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    
    cs_x86 *x86;
    cs_detail *detail;
    cs_insn *insn = cs_malloc(handle);
    
    //printf("1\n");
    
    
    ulong instr_addr = (ulong) uc->uc_mcontext.gregs[REG_RIP];
    uint8_t* code = (uint8_t*) uc->uc_mcontext.gregs[REG_RIP];
    size_t sizeds;
    
    cs_disasm_iter(handle, &code , &sizeds, &instr_addr, insn);
    
    //printf("1\n");
    
    detail = insn->detail;
    x86 = &detail->x86;
    
    //uint8_t fr = (uint8_t) x86->op_count;
    for (size_t i=0; i < x86->op_count; i++){
        if (x86->operands[i].type == X86_OP_MEM) {
            int reg= x86->operands[i].mem.base;
            //printf("%u\n", reg);
            
            switch(reg){
            
            case 35: mod_reg = 13;
                break;
            case 36: mod_reg = 10;
                break;
            case 37: mod_reg = 11;
                break;
            case 38: mod_reg = 14;
                break;
            case 39: mod_reg = 8;
                break;
            case 40: mod_reg = 12;
                break;
            //skipping RIP;
            
            case 43: mod_reg = 9;
                break;
            case 44: mod_reg = 15;
                break;
            }
            
        }
    
    }
    
    cs_free(insn, 1);
    
    // Untaint address 
    long addr = (long) uc->uc_mcontext.gregs[mod_reg];
    long taint = (addr & 0xFFFF000000000000) / 0x1000000000000;
    long org_addr;
    //printf("Taint: %lu\n", taint);
    if(taint != 0) {
	// Bounds checking  
        long base_addr = malloc_metadata[taint-1].baseAddr;
        int obj_size = malloc_metadata[taint-1].length;
        org_addr = (long) ((uc->uc_mcontext.gregs[mod_reg] << 16 ) >> 16 );
        //printf("Base Addr: %lu\n", base_addr);
        //printf("Object size: %u\n", obj_size);
        //printf("Original Address: %lu\n", org_addr);
        if (base_addr <= org_addr && (base_addr + obj_size) >= org_addr){
            // Bounds check succeeded, nothing to do

            //Untaint address
            long org_addr = (long) ((uc->uc_mcontext.gregs[mod_reg] << 16 ) >> 16 );
            uc->uc_mcontext.gregs[mod_reg] = org_addr;
            //printf("Bounds check successful\n");
        }
        else {
            //printf("Bounds check unsuccessful, exit for now\n");
            // Bounds check unsuccessful, exit for now
            exit(-1);
        }
    }
    else {
    printf("Not a tainted address\n");
    exit(-1);
    }
    
    old_malloc_hook = __malloc_hook;
    old_free_hook = __free_hook;
    old_realloc_hook = __realloc_hook;
    
    __malloc_hook = dw_malloc_hook;
    __free_hook = dw_free_hook;
    __realloc_hook = dw_realloc_hook;
    
    uc->uc_mcontext.gregs[mod_reg] = org_addr;
}

extern void
__attribute__((constructor)) dw_init()
{
    int malloc_metadata_size = 356;

    if ((malloc_metadata_size < MALLOC_METADATA_MIN_SIZE) || (malloc_metadata_size > MALLOC_METADATA_MAX_SIZE)) {
        printf("Invalid malloc metadata table size");
        exit(-1);
    }
    
    //init metadata

    malloc_metadata = malloc(sizeof(object_id) * malloc_metadata_size);

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
   
    struct sigaction sa;

    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    sa.sa_sigaction = sigsegv_handler;
    sigaction(SIGSEGV, &sa, NULL);
    sigaction(SIGBUS, &sa, NULL);
    
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

