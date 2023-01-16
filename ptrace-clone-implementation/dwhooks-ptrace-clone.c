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
#include <sys/ptrace.h>
#include <sys/user.h>
#include <errno.h>
#include <sched.h>

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

static int
child_program(void* malloc_addr){


	// Attach to "parent" thread
	
	// Get "parent" pid
	int ppid = getppid();
	
	// Attach to "parent" pid
	int err = ptrace(PTRACE_ATTACH, ppid, NULL, NULL);
	int status;
	
	// Open file for logging
	FILE *fs;
	fs = fopen("tmp.txt","w");
	fputs("a\n",fs);
	
	
    struct user_regs_struct regs;
	
	while(1){
	
		// Wait for interruption signal
		waitpid(ppid,&status,0);
		
		if (WIFEXITED(status)){
                break;
            }
        ptrace(PTRACE_GETREGS, ppid, NULL, &regs);
        fputs("Caught exception\n",fs);
        
        // Capstone
		csh handle;
            
        if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK){
            //printf("Capstone was unable to open");
            break;
        }
            
        cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
            
        cs_x86 *x86;
        cs_detail *detail;
        cs_insn *insn = cs_malloc(handle);
        
        
        ulong instr_addr = (ulong) regs.rip;
    	uint8_t* code = (uint8_t*) regs.rip;
    	size_t sizeds;
    
    	cs_disasm_iter(handle, &code , &sizeds, &instr_addr, insn);
        
        detail = insn->detail;
    	x86 = &detail->x86;
    	
    	fprintf(fs,"Caught exception\n");
    	
    	long addr;
        int reg;
    	for (size_t i=0; i < x86->op_count; i++){
            if (x86->operands[i].type == X86_OP_MEM) {
                reg= x86->operands[i].mem.base;
                
                fprintf(fs,"Memory register: %u\n",reg);    
                    
                switch(reg){
                // RAX
                case 35: addr = regs.rax;
                    break;
                // RBP
                case 36: addr = regs.rbp;
                    break;
                // RBX
                case 37: addr = regs.rbx;
                    break;
                // RCX
                case 38: addr = regs.rcx;
                    break;
                // RDI
                case 39: addr = regs.rdi;
                    break;
                // RDX
                case 40: addr = regs.rdx;
                    break;
                //skipping RIP;
                // RSI
                case 43: addr = regs.rsi;
                    break;
                // RSP
                case 44: addr = regs.rsp;
                    break;
                // R14
                case 112: addr = regs.r14;
                	break;
                }
            }
        
        }
        cs_free(insn, 1);
        long taint = (addr & 0xFFFF000000000000) / 0x1000000000000;
            long org_addr;
            //printf("Taint: %lu\n", taint);
            if(taint != 0) {
	        // Bounds checking  
	        	void *child_addr = malloc_addr + ((taint - 1) * 24);
	        	
	        	long base_addr = *(long*)child_addr;
	        	void *child_size = child_addr+8;
                long obj_size = *(long*)child_size;
                org_addr = (long) ((addr << 16 ) >> 16 );
                
                if (base_addr <= org_addr && (base_addr + obj_size) >= org_addr){
                    // Bounds check succeeded, nothing to do
                    
                    switch(reg){
                    // RAX
                    case 35: 
                        regs.rax = org_addr;
                        ptrace(PTRACE_SETREGS,ppid,NULL,&regs);
                        ptrace(PTRACE_SINGLESTEP,ppid,NULL,NULL);
                        ptrace(PTRACE_GETREGS,ppid,NULL,&regs);
                        regs.rax = addr;
                        ptrace(PTRACE_SETREGS,ppid,NULL,&regs);
                        break;
                    // RBP
                    case 36: 
                        regs.rbp = org_addr;
                        ptrace(PTRACE_SETREGS,ppid,NULL,&regs);
                        ptrace(PTRACE_SINGLESTEP,ppid,NULL,NULL);
                        ptrace(PTRACE_GETREGS,ppid,NULL,&regs);
                        regs.rbp = addr;
                        ptrace(PTRACE_SETREGS,ppid,NULL,&regs);
                        break;
                    // RBX
                    case 37: 
                        regs.rbx = org_addr;
                        ptrace(PTRACE_SETREGS,ppid,NULL,&regs);
                        ptrace(PTRACE_SINGLESTEP,ppid,NULL,NULL);
                        ptrace(PTRACE_GETREGS,ppid,NULL,&regs);
                        regs.rbx = addr;
                        ptrace(PTRACE_SETREGS,ppid,NULL,&regs);
                        break;
                    // RCX
                    case 38: 
                        regs.rcx = org_addr;
                        ptrace(PTRACE_SETREGS,ppid,NULL,&regs);
                        ptrace(PTRACE_SINGLESTEP,ppid,NULL,NULL);
                        ptrace(PTRACE_GETREGS,ppid,NULL,&regs);
                        regs.rcx = addr;
                        ptrace(PTRACE_SETREGS,ppid,NULL,&regs);
                        break;
                    // RDI
                    case 39: 
                        regs.rdi = org_addr;
                        ptrace(PTRACE_SETREGS,ppid,NULL,&regs);
                        ptrace(PTRACE_SINGLESTEP,ppid,NULL,NULL);
                        ptrace(PTRACE_GETREGS,ppid,NULL,&regs);
                        regs.rdi = addr;
                        ptrace(PTRACE_SETREGS,ppid,NULL,&regs);
                        break;
                    // RDX
                    case 40: 
                        regs.rdx = org_addr;
                        ptrace(PTRACE_SETREGS,ppid,NULL,&regs);
                        ptrace(PTRACE_SINGLESTEP,ppid,NULL,NULL);
                        ptrace(PTRACE_GETREGS,ppid,NULL,&regs);
                        regs.rdx = addr;
                        ptrace(PTRACE_SETREGS,ppid,NULL,&regs);
                        break;
                    //skipping RIP;
                    // RSI
                    case 43: 
                        regs.rsi = org_addr;
                        ptrace(PTRACE_SETREGS,ppid,NULL,&regs);
                        ptrace(PTRACE_SINGLESTEP,ppid,NULL,NULL);
                        ptrace(PTRACE_GETREGS,ppid,NULL,&regs);
                        regs.rsi = addr;
                        ptrace(PTRACE_SETREGS,ppid,NULL,&regs);
                        break;
                    // RSP
                    case 44: addr = regs.rsp;
                        break;
                    case 112: 
                    	regs.r14 = org_addr;
                        ptrace(PTRACE_SETREGS,ppid,NULL,&regs);
                        ptrace(PTRACE_SINGLESTEP,ppid,NULL,NULL);
                        ptrace(PTRACE_GETREGS,ppid,NULL,&regs);
                        regs.r14 = addr;
                        ptrace(PTRACE_SETREGS,ppid,NULL,&regs);
                        break;
                    }
                    
                    printf("Bounds check successful\n");
                }
                else {
                    //printf("Bounds check unsuccessful, exit for now\n");
                    // Bounds check unsuccessful, exit for now
                    //exit(-1);
                }
            }
    	
            
    }
    fclose(fs);
    return 1;

}

extern void
__attribute__((constructor)) dw_init()
{
    int malloc_metadata_size = 356;
	//printf("2\n");
    
    
    if ((malloc_metadata_size < MALLOC_METADATA_MIN_SIZE) || (malloc_metadata_size > MALLOC_METADATA_MAX_SIZE)) {
        //printf("Invalid malloc metadata table size");
        exit(-1);
    }
    
    //init metadata

    malloc_metadata = malloc(sizeof(object_id) * malloc_metadata_size);
    int *malloc_addr = malloc_metadata;
    
    // Pass the addr of the malloc metadata to the "child"
    int ppid = getpid();
    const int STACK_SIZE = 65536;
    char* stack = malloc(STACK_SIZE);
    int child = clone(child_program, stack + STACK_SIZE, CLONE_VM, malloc_addr);
	
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

