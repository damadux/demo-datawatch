#define _GNU_SOURCE

#include <malloc.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <capstone/capstone.h>
#include <errno.h>
#include <unistd.h>
#include <dlfcn.h>

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

int main(int argc, char **argv)
{
    if (argc != 1){
        printf("argument needed: command to run with ptrace");
    }
    
    void* handle;
    
    int malloc_metadata_size = 356;

	old_malloc_hook = __malloc_hook;
    old_free_hook = __free_hook;
    old_realloc_hook = __realloc_hook;

	/**
	handle = dlopen("./libdw2.so", RTLD_NOW | RTLD_NODELETE);
	if (!handle) {
        fprintf(stderr, "%s\n", dlerror());
        exit(EXIT_FAILURE);
    }
    */
    pid_t child;
    child = fork();
    if (child == 0) {
        char* parmList[] = {"ls", NULL};
        /*
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
		**/
        
        char* envp[] = {"LD_PRELOAD=/home/davidpiche/Documents/gitdw/demo-datawatch/libdw2.so", NULL};
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        int f = execve("/bin/ls", parmList, envp);
        int *e = malloc(sizeof(int));
    }
    else {
    
    	__malloc_hook = old_malloc_hook;
        __free_hook = old_free_hook;
        __realloc_hook = old_realloc_hook;
        
        int status;
        struct user_regs_struct regs;
    
        while(1){
            wait(&status);
            if (WIFEXITED(status)){
            	printf("a");
                break;
            }
            
            int res = WSTOPSIG(status);
            if (res == 5){
            	//continue;
            	printf("stop\n");
            }
            ptrace(PTRACE_GETREGS, child, NULL, &regs);
            
            // Disassemble the instruction
            csh handle;
            
            if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK){
                printf("Capstone was unable to open");
                break;
            }
            
            cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
            
            cs_x86 *x86;
            cs_detail *detail;
            //cs_insn *insn = cs_malloc(handle);
            cs_insn *insn;
            
            ulong instr_addr = (ulong) regs.rip;
            uint8_t codes[8];
            ((uint32_t*)codes)[0] = ptrace(PTRACE_PEEKTEXT, child, regs.rip, 0);
            ((uint32_t*)codes)[1] = ptrace(PTRACE_PEEKTEXT, child, regs.rip + 4, 0);
            size_t count;
            /*
            size_t sizeds;
            
            uint8_t* code = (uint8_t*)regs.rip;
            
            if (res == 5){
            	//code = (uint8_t*)regs.rip;
            }
            */
            //cs_disasm_iter(handle, &code , &sizeds, &instr_addr, insn);
            count = cs_disasm(handle, codes, sizeof(codes), instr_addr, 1, &insn);
            
            for (size_t j = 0; j < count; j++){
            	detail = insn[j].detail;
            }
            x86 = &detail->x86;
            int errno1 = cs_errno(handle);
            long addr;
            int reg;
            for (size_t i=0; i < x86->op_count; i++){
                int type = x86->operands[i].type;
                if (x86->operands[i].type == X86_OP_MEM) {
                    reg= x86->operands[i].mem.base;
                    
                    
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
                    }
                    
                }
            
            }
            errno1 = cs_errno(handle);
            cs_free(insn, 1);
            
            // Untaint address 
            long taint = (addr & 0xFFFF000000000000) / 0x1000000000000;
            long org_addr;
            //printf("Taint: %lu\n", taint);
            if(taint != 0) {
	        // Bounds checking  
	        	void *child_addr = 0x5555558f66b0 + ((taint - 1) * 24);
	        	long base_addr = ptrace(PTRACE_PEEKDATA, child, child_addr, 0);
	        	//printf("%lu", base_addr);
	        	child_addr += 8;
                //long base_addr = malloc_metadata[taint-1].baseAddr;
                long obj_size = ptrace(PTRACE_PEEKDATA, child, child_addr, 0);
                org_addr = (long) ((addr << 16 ) >> 16 );
                //printf("Base Addr: %lu\n", base_addr);
                //printf("Object size: %u\n", obj_size);
                //printf("Original Address: %lu\n", org_addr);
                if (base_addr <= org_addr && (base_addr + obj_size) >= org_addr){
                    // Bounds check succeeded, nothing to do
                    
                    switch(reg){
                    // RAX
                    case 35: 
                        regs.rax = org_addr;
                        ptrace(PTRACE_SETREGS,child,NULL,&regs);
                        ptrace(PTRACE_SINGLESTEP,child,NULL,NULL);
                        ptrace(PTRACE_GETREGS,child,NULL,&regs);
                        regs.rax = addr;
                        break;
                    // RBP
                    case 36: 
                        regs.rbp = org_addr;
                        ptrace(PTRACE_SETREGS,child,NULL,&regs);
                        ptrace(PTRACE_SINGLESTEP,child,NULL,NULL);
                        ptrace(PTRACE_GETREGS,child,NULL,&regs);
                        regs.rbp = addr;
                        break;
                    // RBX
                    case 37: 
                        regs.rbx = org_addr;
                        ptrace(PTRACE_SETREGS,child,NULL,&regs);
                        ptrace(PTRACE_SINGLESTEP,child,NULL,NULL);
                        ptrace(PTRACE_GETREGS,child,NULL,&regs);
                        regs.rbx = addr;
                        break;
                    // RCX
                    case 38: 
                        regs.rcx = org_addr;
                        ptrace(PTRACE_SETREGS,child,NULL,&regs);
                        ptrace(PTRACE_SINGLESTEP,child,NULL,NULL);
                        ptrace(PTRACE_GETREGS,child,NULL,&regs);
                        regs.rcx = addr;
                        break;
                    // RDI
                    case 39: 
                        regs.rdi = org_addr;
                        ptrace(PTRACE_SETREGS,child,NULL,&regs);
                        ptrace(PTRACE_SINGLESTEP,child,NULL,NULL);
                        ptrace(PTRACE_GETREGS,child,NULL,&regs);
                        regs.rdi = addr;
                        break;
                    // RDX
                    case 40: 
                        regs.rdx = org_addr;
                        ptrace(PTRACE_SETREGS,child,NULL,&regs);
                        ptrace(PTRACE_SINGLESTEP,child,NULL,NULL);
                        ptrace(PTRACE_GETREGS,child,NULL,&regs);
                        regs.rdx = addr;
                        break;
                    //skipping RIP;
                    // RSI
                    case 43: 
                        regs.rsi = org_addr;
                        ptrace(PTRACE_SETREGS,child,NULL,&regs);
                        ptrace(PTRACE_SINGLESTEP,child,NULL,NULL);
                        ptrace(PTRACE_GETREGS,child,NULL,&regs);
                        regs.rsi = addr;
                        break;
                    // RSP
                    case 44: addr = regs.rsp;
                        break;
                    }
                    
                    //printf("Bounds check successful\n");
                }
                else {
                    //printf("Bounds check unsuccessful, exit for now\n");
                    // Bounds check unsuccessful, exit for now
                    //exit(-1);
                }
            }
            else {
            printf("Not a tainted address\n");
            
            //exit(-1);
            }
            
            ptrace(PTRACE_CONT, child, NULL, NULL);
        
        
        }
    
    }
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
   
