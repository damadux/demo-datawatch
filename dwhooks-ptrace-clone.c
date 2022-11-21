#define _GNU_SOURCE

#include <malloc.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <capstone/capstone.h>
#include <errno.h>
#include <unistd.h>
#include <dlfcn.h>
#include <sched.h>

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

static int child_program(void* arg) {
	char* parmList[] = {"git", NULL};
	char* envp[] = {"LD_PRELOAD=/home/davidpiche/Documents/gitdw/demo-datawatch/libdw2.so", NULL};
    ptrace(PTRACE_TRACEME, 0, NULL, NULL);
    char* args = (char*)arg;
    int f = execve((char*)arg, parmList, envp);
	return 0;
}


int main(int argc, char **argv)
{
    if (argc != 1){
        printf("argument needed: command to run with ptrace");
    }
    
    void* handle;
    
    int malloc_metadata_size = 356;

    char* buf = "/bin/git";
    pid_t child;
    const int STACK_SIZE = 65536;
    char* stack = malloc(STACK_SIZE);
    child = clone(child_program, stack + STACK_SIZE, CLONE_VM, buf);
    
    
        
    int status;
    struct user_regs_struct regs;

    while(1){
        waitpid(child, &status, __WCLONE);
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
    	uint8_t* code = (uint8_t*) regs.rip;
    	size_t sizeds;
    
    	cs_disasm_iter(handle, &code , &sizeds, &instr_addr, insn);
        /*
        size_t sizeds;
        
        uint8_t* code = (uint8_t*)regs.rip;
        
        if (res == 5){
        	//code = (uint8_t*)regs.rip;
        }
        */
        //cs_disasm_iter(handle, &code , &sizeds, &instr_addr, insn);
        //count = cs_disasm(handle, codes, sizeof(codes), instr_addr, 1, &insn);
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
        	long base_addr = 50;
        	//printf("%lu", base_addr);
        	child_addr += 8;
            //long base_addr = malloc_metadata[taint-1].baseAddr;
            long obj_size = 50;
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

   
