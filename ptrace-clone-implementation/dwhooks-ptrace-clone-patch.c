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
#include <sys/wait.h>
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

static __thread int malloc_hook_active = 0;
static __thread int realloc_hook_active = 0;
static __thread int free_hook_active = 0;
static int ppid, ptid, cpid;

static volatile long dw_TAG; // A constant tag to store in the top 16 bits of any new pointer
static volatile uintptr_t dw_MASK;

/* Table of malloc objects tracked by tainted pointers
   The taint is the index + 1 since a taint of 0 would not
   trigger a SIGSEGV. With the base_addr and the size, we can check
   if the bytes accessed are within the allocated bounds for the object.
   
   The status field serves dual purpose. It contains -2 when the entry is
   in use and contains the index of the next entry in the free list when
   the entry is not in use, or -1 if it is the last item in the list. */
   
static struct object_id {
    void *base_addr;
    size_t size;
    int status;
} object_id;

static struct object_id *malloc_metadata;  // CHECK volatile
static int malloc_metadata_size = 356;

int head = -1;

static int
get_reg(int reg, struct user_regs_struct *regs, long long unsigned *value) {
    int ret = 0;
    switch(reg) {
        case 35: *value = regs->rax; break;
        case 36: *value = regs->rbp; break;
        case 37: *value = regs->rbx; break;
        case 38: *value = regs->rcx; break;
        case 39: *value = regs->rdi; break;
        case 40: *value = regs->rdx; break;
        //skipping RIP;
        case 43: *value = regs->rsi; break;
        case 44: *value = regs->rsp; break;
        case 106: *value = regs->r8; break;
        case 107: *value = regs->r9; break;
        case 108: *value = regs->r10; break;
        case 109: *value = regs->r11; break;
        case 110: *value = regs->r12; break;
        case 111: *value = regs->r13; break;
        case 112: *value = regs->r14; break;
        case 113: *value = regs->r15; break;
        default: ret = -1;
    }
    return ret;
}

static int
set_reg(int reg, struct user_regs_struct *regs, long long unsigned value) {
    int ret = 0;
    switch(reg) {
        case 35: regs->rax = value; break;
        case 36: regs->rbp = value; break;
        case 37: regs->rbx = value; break;
        case 38: regs->rcx = value; break;
        case 39: regs->rdi = value; break;
        case 40: regs->rdx = value; break;
        //skipping RIP;
        case 43: regs->rsi = value; break;
        case 44: regs->rsp = value; break;
        case 106: regs->r8 = value; break;
        case 107: regs->r9 = value; break;
        case 108: regs->r10 = value; break;
        case 109: regs->r11 = value; break;
        case 110: regs->r12 = value; break;
        case 111: regs->r13 = value; break;
        case 112: regs->r14 = value; break;
        case 113: regs->r15 = value; break;
        default: ret = -1;
    }
    return ret;
}

static int
child_program(void* malloc_addr) {

    malloc_hook_active = 0;
    realloc_hook_active = 0;
    free_hook_active = 0;
    
    fprintf(stderr,"Child_program started, parent id %d, pid %d, tid %d\n", getppid(), getpid(), gettid());
    
    // Attach to "parent" thread

    int err = ptrace(PTRACE_ATTACH, ptid, NULL, NULL);
    if(err < 0) {
        fprintf(stderr,"Child_program not attached ptrace returns %d, errno %d\n", err, errno);
    } else fprintf(stderr,"Child_program attached %d\n", err);
        
    int status;	
    struct user_regs_struct regs;

    // Capstone
    csh handle;

    cs_err csres = cs_open(CS_ARCH_X86, CS_MODE_64, &handle);
    // fprintf(stderr, "cs_open returned %d\n", csres);
    csres = cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    // fprintf(stderr, "cs_option returned %d\n", csres);
            
    cs_x86 *x86;
    cs_detail *detail;
    cs_insn *insn = cs_malloc(handle);
    // fprintf(stderr, "cs_malloc rerurned %p\n", insn);

    while(1){
	
        // Wait for interruption signal
        waitpid(ptid,&status,0);
		
	if (WIFEXITED(status)) break;

        ptrace(PTRACE_GETREGS, ppid, NULL, &regs);
        fprintf(stderr,"Caught exception\n");
        
        if(WIFSTOPPED(status)) {
            int s = WSTOPSIG(status);
            fprintf(stderr, "Traced process stopped by signal %d\n", s);
            if(s != SIGSEGV && s != SIGBUS) {
                ptrace(PTRACE_CONT,ppid,NULL,NULL);
                continue;
            }
        }   
        else fprintf(stderr, "Traced process not exited nor stopped by a signal??\n");
        
        uint64_t instr_addr = (uint64_t) regs.rip;
    	const uint8_t *code = (uint8_t *) regs.rip;
    	size_t sizeds = 100;
    
    	// fprintf(stderr, "Disassemble instruction at %llx\n", regs.rip);
    	bool success = cs_disasm_iter(handle, &code , &sizeds, &instr_addr, insn);
        // fprintf(stderr, "cs_disasm_iter returned %d with code %d\n", success, cs_errno(handle));
    	fprintf(stderr, "%lx: %s %s, (%hu)\n", insn->address, insn->mnemonic, insn->op_str, insn->size);
        
        detail = insn->detail;
    	x86 = &detail->x86;
    	if(x86->op_count < 1) abort();
    	
    	long long unsigned addr;
        int reg = -1;
        int dest_reg = -1;
        
    	for (size_t i=0; i < x86->op_count; i++){
    	    if(x86->operands[i].type == X86_OP_REG && x86->operands[i].access & CS_AC_WRITE) {
    	        dest_reg = x86->operands[i].reg;
    	    }
            else if (x86->operands[i].type == X86_OP_MEM) {
                reg= x86->operands[i].mem.base;
                if(get_reg(reg, &regs, &addr) < 0) {
                    fprintf(stderr, "Unhandled register %d, we are doomed\n", reg);
                    abort();
                }
                fprintf(stderr, "Memory register: %u\n", reg);       
            }
        
        }
        
        unsigned long taint = addr >> 48;
        long index = taint - 1;
        long long unsigned org_addr = ((addr << 16 ) >> 16 );
        long long unsigned new_addr;

        fprintf(stderr,"Addr %llx, taint %lu, org_addr %llx, reg %d, dest_reg %d\n", addr, taint, org_addr, reg, dest_reg);

        if(taint != 0) {
            if(index < 0 || index > malloc_metadata_size - 1) {
                fprintf(stderr, "Program has invalid taint\n");
                abort();
            }
	    // Bounds checking  
	    void *base_addr = malloc_metadata[index].base_addr;
	    size_t obj_size = malloc_metadata[index].size;
                
            if ((void *)org_addr >= base_addr && (void *)org_addr < (base_addr + obj_size)) {  // CHECK, we should know the number of bytes accessed
                // Bounds check succeeded, nothing to do
                fprintf(stderr, "Bounds check successful\n");
            }
            else {
                fprintf(stderr, "Bounds check unsuccessful, addr %llx, taint %lu, base addr %p, size %lu\n", addr, taint, base_addr, obj_size);
                // Bounds check unsuccessful, exit for now
                //exit(-1);
            }

            if(set_reg(reg, &regs, org_addr) < 0) {
                fprintf(stderr, "Unhandled register %d, we are doomed\n", reg);
                abort();
            }
            ptrace(PTRACE_SETREGS,ppid,NULL,&regs);
            ptrace(PTRACE_SINGLESTEP,ppid,NULL,NULL);
            waitpid(ptid,&status,0);
            if(WIFEXITED(status)) break;
            if(WIFSTOPPED(status)) {
                int s = WSTOPSIG(status);
                if(s != SIGTRAP) {
                    fprintf(stderr, "Single step not followed by trap, %d\n", s);
                }
            }

            ptrace(PTRACE_GETREGS,ppid,NULL,&regs);
            get_reg(reg, &regs, &new_addr);
            if(reg == dest_reg) {
                if(org_addr != new_addr) fprintf(stderr, "Memory base register is also destination register and modified, do not retaint\n");
                else fprintf(stderr, "STRANGE Memory base register is also destination register but not modified, do not retaint\n");
            }
            else if(org_addr != new_addr) fprintf(stderr, "STRANGE Memory base register modified but should not, do not retaint\n");
            else {
                set_reg(reg, &regs, addr);
                ptrace(PTRACE_SETREGS,ppid,NULL,&regs);
            }
        }
        else {
            fprintf(stderr, "SIGSEGV without taint, we are doomed\n");
            abort();
        }
        ptrace(PTRACE_CONT,ppid,NULL,NULL);
    }
    cs_free(insn, 1);
    cs_close(&handle);
    return 1;
}

extern void
__attribute__((constructor)) dw_init()
{
    if ((malloc_metadata_size < MALLOC_METADATA_MIN_SIZE) || (malloc_metadata_size > MALLOC_METADATA_MAX_SIZE)) {
        //printf("Invalid malloc metadata table size");
        exit(-1);
    }
    
    //init metadata

    malloc_metadata = malloc(sizeof(object_id) * malloc_metadata_size);
    void *malloc_addr = (void *)malloc_metadata; // CHECK dropping volatile!?!
    
    // Pass the addr of the malloc metadata to the "child"
    ppid = getpid();
    ptid = gettid();
    fprintf(stderr, "Process id of main thread %d, thread id %d\n", ppid, ptid);
    
    const int STACK_SIZE = 65536;
    char* stack = malloc(STACK_SIZE);
    cpid = clone(child_program, stack + STACK_SIZE, CLONE_VM, malloc_addr);
    fprintf(stderr, "Clone child created %d\n", cpid);

    // Put all the entries in the free list to start.
    // status gives the next in list or -1 at the end.
    for(int i=0;i<malloc_metadata_size;i++){
        malloc_metadata[i].status = i + 1;
    }
    malloc_metadata[malloc_metadata_size - 1].status = -1;
    head = 0;

    sleep(2); /* we should wait for child to have attached */
    fprintf(stderr,"DDW: Init completed\n");
    fprintf(stderr, "Setting hooks active from %d\n", gettid());
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
    fprintf(stderr,"Malloc_hook called %p\n", result);
   
    /* Encode the object metadata */
    if (head == -1){
        // Free list is empty, stop tainting new objects for now
    }
    else {
        int next_head = malloc_metadata[head].status;
        malloc_metadata[head].status = -2;
        malloc_metadata[head].base_addr = result;
        malloc_metadata[head].size = size;

        //printf("Object_id: %u \n", head);
        //printf("BaseAddr: %p \n", result);
        //printf("Length: %zu \n", size);

        result = (void *)(((uintptr_t)result) | ((uintptr_t)(head + 1) << 48));    
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

    //long addr = (long) ptr;
    //printf("Address freed: %lu\n",addr);

    unsigned long taint = (long long unsigned)ptr >> 48;
    long index = taint - 1;

    if(taint != 0) {
        if(index < 0 || index > malloc_metadata_size - 1) {
            fprintf(stderr, "Invalid taint value %lu\n", taint);
            return;
        }
        if (malloc_metadata[index].status == -2) {
            malloc_metadata[index].status = head;
            head = index;
        }
        else {
            fprintf(stderr, "Error in Free_hook\n");
        }

        //  Untaint
        ptr = (void *)(((intptr_t) ptr << 16) >> 16);
    }
    
    /* Call recursively */
    fprintf(stderr,"Free_hook called %p\n", ptr);
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
    long index = taint-1;
    ptr = (void *)(((intptr_t) ptr << 16) >> 16);

    if(taint == 0) result = __libc_realloc(ptr,size);
    
    else if(index < 0 || index > malloc_metadata_size - 1) {
        fprintf(stderr, "Invalid taint value %lu\n", taint);
    }
    
    else if(malloc_metadata[index].status == -2) {
        void *addr = malloc_metadata[index].base_addr;
        size_t old_size = malloc_metadata[index].size;
        if(addr != ptr) fprintf(stderr, "Not freeing the original address, %p in %p + %lu\n", ptr, addr, old_size); 
        /* Call recursively with untainted address*/
        result = realloc(ptr,size);
        malloc_metadata[index].base_addr = result;
        malloc_metadata[index].size = size;
        result = (void *)(((uintptr_t)result) | ((uintptr_t)taint << 48));    
    }

    else {
        result = __libc_realloc(ptr,size);
    }
    
    fprintf(stderr,"Realloc_hook called %p\n", result);    

    /* Restore our own hooks */
    malloc_hook_active = 1;
    realloc_hook_active = 1;
    free_hook_active = 1;

    return result;
}

void*
malloc (size_t size)
{
        void *ret;
        // fprintf(stderr,"DDW: Malloc called by %d, hook %d, adr hook %p\n", gettid(), malloc_hook_active, &malloc_hook_active);
	void *caller = __builtin_return_address(0);
	if (malloc_hook_active && getpid() != cpid) ret = dw_malloc_hook(size, caller);
	else ret = __libc_malloc(size);
	fprintf(stderr,"Malloc %lu at %p\n", size, ret);
	return ret;
}

void*
realloc (void *ptr, size_t size)
{
        void *ret;
        // fprintf(stderr,"DDW: Realloc called %d, hook %d, adr hook %p\n", gettid(), realloc_hook_active, &realloc_hook_active);
	void *caller = __builtin_return_address(0);
	if (realloc_hook_active && getpid() != cpid) ret = dw_realloc_hook(ptr, size, caller);
	else ret = __libc_realloc(ptr, size);
	fprintf(stderr,"Realloc %lu at %p\n", size, ret);
        return ret;
}

void
free (void *ptr)
{
        fprintf(stderr,"Free %p called\n", ptr);
	void *caller = __builtin_return_address(0);
	if (free_hook_active && getpid() != cpid)
		return dw_free_hook(ptr, caller);
	return __libc_free(ptr);
}

