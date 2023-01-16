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
        char* parmList[] = {"git", NULL};
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
        
        
        char* envp[] = {"LD_PRELOAD=/home/davidpiche/Documents/gitdw/demo-datawatch/libdw3.so", NULL};
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        //int err = ptrace(PTRACE_SETOPTIONS, 0, NULL, PTRACE_O_TRACEEXEC);
        //perror("option");
        int f = execve("/bin/git", parmList, envp);
    }
    else {
        
        unsigned long lo, hi, lo2, hi2;
        
        int status;
        struct user_regs_struct regs;
    
        while(1){
            wait(&status);
            if (WIFEXITED(status)){
            	printf("a");
                break;
            }
            __asm__ __volatile__("rdtsc" : "=a" (lo), "=d" (hi));
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
            
            // Since we do not share virtual memory, we need to extract a certain number of bytes for capstone to disassemble
            ((uint32_t*)codes)[0] = ptrace(PTRACE_PEEKTEXT, child, regs.rip, 0);
            ((uint32_t*)codes)[1] = ptrace(PTRACE_PEEKTEXT, child, regs.rip + 4, 0);
            size_t count;
            count = cs_disasm(handle, codes, sizeof(codes), instr_addr, 1, &insn);
            
            // count should be 1
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
                    // R14
                    case 112: addr = regs.r14;
                    	break;
                    }
                }
            
            }
            errno1 = cs_errno(handle);
            cs_free(insn, 1);
            int er = sysconf(_SC_CLK_TCK);
            // Untaint address 
            long taint = (addr & 0xFFFF000000000000) / 0x1000000000000;
            long org_addr;
            //printf("Taint: %lu\n", taint);
            if(taint != 0) {
	        // Bounds checking  
	        	void *child_addr = 0x5555559326b0 + ((taint - 1) * 24);
	        	
	        	
	        	long base_addr = ptrace(PTRACE_PEEKDATA, child, child_addr, 0);
	        	child_addr += 8;
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
                        ptrace(PTRACE_SETREGS,child,NULL,&regs);
                        break;
                    // RBP
                    case 36: 
                        regs.rbp = org_addr;
                        ptrace(PTRACE_SETREGS,child,NULL,&regs);
                        ptrace(PTRACE_SINGLESTEP,child,NULL,NULL);
                        ptrace(PTRACE_GETREGS,child,NULL,&regs);
                        regs.rbp = addr;
                        ptrace(PTRACE_SETREGS,child,NULL,&regs);
                        break;
                    // RBX
                    case 37: 
                        regs.rbx = org_addr;
                        ptrace(PTRACE_SETREGS,child,NULL,&regs);
                        ptrace(PTRACE_SINGLESTEP,child,NULL,NULL);
                        ptrace(PTRACE_GETREGS,child,NULL,&regs);
                        regs.rbx = addr;
                        ptrace(PTRACE_SETREGS,child,NULL,&regs);
                        break;
                    // RCX
                    case 38: 
                        regs.rcx = org_addr;
                        ptrace(PTRACE_SETREGS,child,NULL,&regs);
                        ptrace(PTRACE_SINGLESTEP,child,NULL,NULL);
                        ptrace(PTRACE_GETREGS,child,NULL,&regs);
                        regs.rcx = addr;
                        ptrace(PTRACE_SETREGS,child,NULL,&regs);
                        break;
                    // RDI
                    case 39: 
                        regs.rdi = org_addr;
                        ptrace(PTRACE_SETREGS,child,NULL,&regs);
                        ptrace(PTRACE_SINGLESTEP,child,NULL,NULL);
                        ptrace(PTRACE_GETREGS,child,NULL,&regs);
                        regs.rdi = addr;
                        ptrace(PTRACE_SETREGS,child,NULL,&regs);
                        break;
                    // RDX
                    case 40: 
                        regs.rdx = org_addr;
                        ptrace(PTRACE_SETREGS,child,NULL,&regs);
                        ptrace(PTRACE_SINGLESTEP,child,NULL,NULL);
                        ptrace(PTRACE_GETREGS,child,NULL,&regs);
                        regs.rdx = addr;
                        ptrace(PTRACE_SETREGS,child,NULL,&regs);
                        break;
                    //skipping RIP;
                    // RSI
                    case 43: 
                        regs.rsi = org_addr;
                        ptrace(PTRACE_SETREGS,child,NULL,&regs);
                        ptrace(PTRACE_SINGLESTEP,child,NULL,NULL);
                        ptrace(PTRACE_GETREGS,child,NULL,&regs);
                        regs.rsi = addr;
                        ptrace(PTRACE_SETREGS,child,NULL,&regs);
                        break;
                    // RSP
                    case 44: addr = regs.rsp;
                        break;
                    case 112: 
                    	regs.r14 = org_addr;
                        ptrace(PTRACE_SETREGS,child,NULL,&regs);
                        ptrace(PTRACE_SINGLESTEP,child,NULL,NULL);
                        ptrace(PTRACE_GETREGS,child,NULL,&regs);
                        regs.r14 = addr;
                        ptrace(PTRACE_SETREGS,child,NULL,&regs);
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
            else {
            printf("Not a tainted address\n");
            
            //exit(-1);
            }
            __asm__ __volatile__("rdtsc" : "=a" (lo2), "=d" (hi2));
	    	lo = lo2 - lo;
	    	printf("%u\n", lo);
            ptrace(PTRACE_CONT, child, NULL, NULL);
            
            
        
        
        }
        
    }
}

