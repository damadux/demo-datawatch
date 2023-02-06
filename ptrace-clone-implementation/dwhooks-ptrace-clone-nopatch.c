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
#include <limits.h>

#include <execinfo.h>
#include <unistd.h>
#include <fcntl.h>
#include <linux/openat2.h>
#include <stdarg.h>
#include <dlfcn.h>
#include <sys/vfs.h>
#include <dirent.h>

#define UNTAINT(adr) ((char *)((long long unsigned)0x0000ffffffffffff & (long long unsigned)adr))

void *dlsym_check(void *restrict handle, const char *restrict symbol) {
    void *ret = dlsym(handle, symbol);
    if(ret == NULL) fprintf(stderr, "Symbol %s not found!\n", symbol);
    return ret;
}

static int (*libc_open)(const char *pathname, int flags, ...);
static int (*libc_openat)(int dirfd, const char *pathname, int flags, ...);
// static int (*libc_openat2)(int dirfd, const char *pathname, const struct open_how *how, size_t size);
static int (*libc_creat)(const char *pathname, mode_t mode);
static int (*libc_access)(const char *pathname, int mode);
static char* (*libc_getcwd)(char *buf, size_t size);
static ssize_t (*libc_getrandom)(void *buf, size_t buflen, unsigned int flags);
static int (*libc_stat)(const char *restrict pathname, struct stat *restrict statbuf);
static int (*libc_fstat)(int fd, struct stat *statbuf);
static int (*libc_lstat)(const char *restrict pathname, struct stat *restrict statbuf);
static int (*libc_fstatat)(int dirfd, const char *restrict pathname, struct stat *restrict statbuf, int flags);
static ssize_t (*libc_pread)(int fd, void *buf, size_t count, off_t offset);
static ssize_t (*libc_pwrite)(int fd, const void *buf, size_t count, off_t offset);
static ssize_t (*libc_read)(int fd, void *buf, size_t count);
static ssize_t (*libc_write)(int fd, const void *buf, size_t count);
static int (*libc_statfs)(const char *path, struct statfs *buf);
static int (*libc_fstatfs)(int fd, struct statfs *buf);
static ssize_t (*libc_getdents64)(int fd, void *dirp, size_t count);

static int init_stubs = 0;
#define iss() if(!init_stubs) init_syscall_stubs()

static void init_syscall_stubs() {
    libc_open = dlsym_check(RTLD_NEXT, "open");
    libc_openat = dlsym_check(RTLD_NEXT, "openat");
//    libc_openat2 = dlsym_check(RTLD_NEXT, "openat2");
    libc_creat = dlsym_check(RTLD_NEXT, "creat");
    libc_access = dlsym_check(RTLD_NEXT, "access");
    libc_getcwd = dlsym_check(RTLD_NEXT, "getcwd");
    libc_getrandom = dlsym_check(RTLD_NEXT, "getrandom");
    libc_stat = dlsym_check(RTLD_NEXT, "stat");
    libc_fstat = dlsym_check(RTLD_NEXT, "fstat");
    libc_lstat = dlsym_check(RTLD_NEXT, "lstat");
    libc_fstatat = dlsym_check(RTLD_NEXT, "fstatat");
    libc_pread = dlsym_check(RTLD_NEXT, "pread");
    libc_pwrite = dlsym_check(RTLD_NEXT, "pwrite");
    libc_read = dlsym_check(RTLD_NEXT, "read");
    libc_write = dlsym_check(RTLD_NEXT, "write");
    libc_statfs = dlsym_check(RTLD_NEXT, "statfs");
    libc_fstatfs = dlsym_check(RTLD_NEXT, "fstatfs");
    libc_getdents64 = dlsym_check(RTLD_NEXT, "getdents64");
    init_stubs = 1;
}

int open(const char *pathname, int flags, ...) { 
    iss(); 
    mode_t mode = 0; 
    if(__OPEN_NEEDS_MODE(flags)) {
        va_list arg; 
        va_start(arg, flags); 
        mode = va_arg(arg, mode_t);
        va_end(arg);
    }
    return libc_open(UNTAINT(pathname), flags, mode); 
}

int openat(int dirfd, const char *pathname, int flags, ...) { 
    iss(); 
    mode_t mode = 0; 
    if(__OPEN_NEEDS_MODE(flags)) {
        va_list arg; 
        va_start(arg, flags); 
        mode = va_arg(arg, mode_t);
        va_end(arg);
    }
    return libc_openat(dirfd, UNTAINT(pathname), flags, mode); 
}

// int openat2(int dirfd, const char *pathname, const struct open_how *how, size_t size) { iss(); return libc_openat2(dirfd, UNTAINT(pathname), how, size); }
int creat(const char *pathname, mode_t mode) { iss(); return libc_creat(UNTAINT(pathname), mode); }
int access(const char *pathname, int mode) { iss(); return libc_access(UNTAINT(pathname), mode); }
char *getcwd(char *buf, size_t size) { iss(); return libc_getcwd(UNTAINT(buf), size); }
ssize_t getrandom(void *buf, size_t buflen, unsigned int flags) { iss(); return libc_getrandom(UNTAINT(buf), buflen, flags); }
int stat(const char *restrict pathname, struct stat *restrict statbuf) { iss(); return libc_stat(UNTAINT(pathname), (struct stat *)UNTAINT(statbuf)); }
int fstat(int fd, struct stat *statbuf) { iss(); return libc_fstat(fd, (struct stat *)UNTAINT(statbuf)); }
int lstat(const char *restrict pathname, struct stat *restrict statbuf) { iss(); return libc_lstat(UNTAINT(pathname), (struct stat *)UNTAINT(statbuf)); }
int fstatat(int dirfd, const char *restrict pathname, struct stat *restrict statbuf, int flags) { iss(); return libc_fstatat(dirfd, UNTAINT(pathname), (struct stat *)UNTAINT(statbuf), flags); }
ssize_t pread(int fd, void *buf, size_t count, off_t offset) { iss(); return libc_pread(fd, (void *)UNTAINT(buf), count, offset); }
ssize_t pwrite(int fd, const void *buf, size_t count, off_t offset) { iss(); return libc_pwrite(fd, (void *)UNTAINT(buf), count, offset); }
ssize_t read(int fd, void *buf, size_t count) { iss(); return libc_read(fd, (void *)UNTAINT(buf), count); }
ssize_t write(int fd, const void *buf, size_t count) { iss(); return libc_write(fd, (void *)UNTAINT(buf), count); }
int statfs(const char *path, struct statfs *buf) { iss(); return libc_statfs(UNTAINT(path), (struct statfs *)UNTAINT(buf)); }
int fstatfs(int fd, struct statfs *buf) { iss(); return libc_fstatfs(fd, (struct statfs *)UNTAINT(buf)); }
ssize_t getdents64(int fd, void *dirp, size_t count) { iss(); return libc_getdents64(fd, (void *)UNTAINT(dirp), count); }

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
static size_t min_taint_size = 0, max_taint_size = ULONG_MAX;

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
        case X86_REG_RAX: *value = regs->rax; break;
        case X86_REG_RBP: *value = regs->rbp; break;
        case X86_REG_RBX: *value = regs->rbx; break;
        case X86_REG_RCX: *value = regs->rcx; break;
        case X86_REG_RDI: *value = regs->rdi; break;
        case X86_REG_RDX: *value = regs->rdx; break;
        case X86_REG_RSI: *value = regs->rsi; break;
        case X86_REG_RSP: *value = regs->rsp; break;
        case X86_REG_R8: *value = regs->r8; break;
        case X86_REG_R9: *value = regs->r9; break;
        case X86_REG_R10: *value = regs->r10; break;
        case X86_REG_R11: *value = regs->r11; break;
        case X86_REG_R12: *value = regs->r12; break;
        case X86_REG_R13: *value = regs->r13; break;
        case X86_REG_R14: *value = regs->r14; break;
        case X86_REG_R15: *value = regs->r15; break;
        default: ret = -1;
    }
    return ret;
}

static int
set_reg(int reg, struct user_regs_struct *regs, long long unsigned value) {
    int ret = 0;
    switch(reg) {
        case X86_REG_RAX: regs->rax = value; break;
        case X86_REG_RBP: regs->rbp = value; break;
        case X86_REG_RBX: regs->rbx = value; break;
        case X86_REG_RCX: regs->rcx = value; break;
        case X86_REG_RDI: regs->rdi = value; break;
        case X86_REG_RDX: regs->rdx = value; break;
        case X86_REG_RSI: regs->rsi = value; break;
        case X86_REG_RSP: regs->rsp = value; break;
        case X86_REG_R8: regs->r8 = value; break;
        case X86_REG_R9: regs->r9 = value; break;
        case X86_REG_R10: regs->r10 = value; break;
        case X86_REG_R11: regs->r11 = value; break;
        case X86_REG_R12: regs->r12 = value; break;
        case X86_REG_R13: regs->r13 = value; break;
        case X86_REG_R14: regs->r14 = value; break;
        case X86_REG_R15: regs->r15 = value; break;
        default: ret = -1;
    }
    return ret;
}

static int
child_program(void* malloc_addr) {

    malloc_hook_active = 0;
    realloc_hook_active = 0;
    free_hook_active = 0;
    
    fprintf(stderr,"INFO Child_program started, parent id %d, pid %d, tid %d\n", getppid(), getpid(), gettid());
    
    // Attach to "parent" thread

    int err = ptrace(PTRACE_ATTACH, ptid, NULL, NULL);
    if(err < 0) {
        fprintf(stderr,"Child_program not attached ptrace returns %d, errno %d\n", err, errno);
    } else fprintf(stderr,"INFO Child_program attached %d\n", err);
        
    int status;	
    struct user_regs_struct regs;

    // Capstone
    csh handle;

    cs_err csres = cs_open(CS_ARCH_X86, CS_MODE_64, &handle);
    if(csres != CS_ERR_OK) fprintf(stderr, "cs_open failed, returned %d\n", csres);
    csres = cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
            
    cs_x86 *x86;
    cs_detail *detail;
    cs_insn *insn = cs_malloc(handle);

    while(1){
	
        // Wait for interruption signal
        waitpid(ptid, &status, 0);
		
	if (WIFEXITED(status)) {
	    fprintf(stderr, "Traced process exited\n");
	    break;
	}

        int s = 0;
        if(WIFSTOPPED(status)) {
            s = WSTOPSIG(status);
            if(s != SIGSEGV && s != SIGBUS) {
                fprintf(stderr, "Traced process stopped by other signal %d, continuing\n", s);
                ptrace(PTRACE_CONT,ppid,NULL,NULL);
                continue;
            }
        }   
        else fprintf(stderr, "Traced process not exited nor stopped by a signal??\n");
        
        ptrace(PTRACE_GETREGS, ppid, NULL, &regs);
        uint64_t instr_addr = (uint64_t) regs.rip;
    	const uint8_t *code = (uint8_t *) regs.rip;
    	size_t sizeds = 100;
    
    	bool success = cs_disasm_iter(handle, &code , &sizeds, &instr_addr, insn);
    	fprintf(stderr, "INFO Signal %d, disasm %llx (%d, %d), %lx: %s %s, (%hu)\n", s, regs.rip, success, cs_errno(handle), insn->address, insn->mnemonic, insn->op_str, insn->size);
        
        detail = insn->detail;
    	x86 = &detail->x86;
    	if(x86->op_count < 1) { fprintf(stderr, "Received SIGSEGV but instruction has no argument\n"); abort(); }
    	
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
            }
        
        }
        
        unsigned long taint = addr >> 48;
        long index = taint - 1;
        long long unsigned org_addr = ((addr << 16 ) >> 16 );
        long long unsigned new_addr;

        fprintf(stderr, "INFO Addr %llx, taint %lu, org_addr %llx, reg %d, dest_reg %d\n", addr, taint, org_addr, reg, dest_reg);

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
                // fprintf(stderr, "Bounds check successful\n");
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
                if(org_addr != new_addr) fprintf(stderr, "INFO Memory base register is also destination register and modified, do not retaint\n");
                else fprintf(stderr, "STRANGE Memory base register is also destination register but not modified, do not retaint\n");
            }
            else if(org_addr != new_addr) fprintf(stderr, "STRANGE Memory base register modified but should not, do not retaint org_addr %llx, new_addr %llx \n", org_addr, new_addr);
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
    char *arg = getenv("DW_MIN_SIZE");
    if(arg != NULL) min_taint_size = atol(arg);
    arg = getenv("DW_MAX_SIZE");
    if(arg != NULL) max_taint_size = atol(arg);    
    fprintf(stderr, "INFO Min taint size %lu, max taint size %lu\n", min_taint_size, max_taint_size);

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
    fprintf(stderr, "INFO Process id of main thread %d, thread id %d\n", ppid, ptid);
    
    const int STACK_SIZE = 65536;
    char* stack = malloc(STACK_SIZE);
    cpid = clone(child_program, stack + STACK_SIZE, CLONE_VM, malloc_addr);
    fprintf(stderr, "INFO Clone child created %d\n", cpid);

    // Put all the entries in the free list to start.
    // status gives the next in list or -1 at the end.
    for(int i=0;i<malloc_metadata_size;i++){
        malloc_metadata[i].status = i + 1;
    }
    malloc_metadata[malloc_metadata_size - 1].status = -1;
    head = 0;

    sleep(2); /* we should wait for child to have attached */
    fprintf(stderr,"INFO Init completed\n");
    fprintf(stderr, "INFO Setting hooks active from %d\n", gettid());
    malloc_hook_active = 1;
    realloc_hook_active = 1;
    free_hook_active = 1;
}

static void *
dw_malloc_hook(size_t size)
{
    void *result, *final_result;

    /* Deactivate all hooks */
    malloc_hook_active = 0;
    realloc_hook_active = 0;
    free_hook_active = 0;

    /* Call recursively */
    final_result = result = __libc_malloc(size);
   
    /* Encode the object metadata */
    if (head == -1){
        fprintf(stderr, "Mallok hook while object table full!\n");
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

        final_result = (void *)(((uintptr_t)result) | ((uintptr_t)(head + 1) << 48));    
        head = next_head;
    }
    /* Restore our own hooks */
    malloc_hook_active = 1;
    realloc_hook_active = 1;
    free_hook_active = 1;
    fprintf(stderr,"INFO Malloc_hook %p (%p), size %lu\n", result, final_result, size);

    return final_result;
}

static void
dw_free_hook (void *ptr)
{
    void *final_ptr;
    
    /* Restore all old hooks */
    malloc_hook_active = 0;
    realloc_hook_active = 0;
    free_hook_active = 0;

    final_ptr = ptr;
    unsigned long taint = (long long unsigned)ptr >> 48;
    long index = taint - 1;

    if(taint != 0) {
        if(index < 0 || index > malloc_metadata_size - 1) {
            fprintf(stderr, "Invalid taint value %lu\n", taint);
        }
        else if (malloc_metadata[index].status == -2) {
            malloc_metadata[index].status = head;
            head = index;
        }
        else {
            fprintf(stderr, "Error in Free_hook\n");
        }

        //  Untaint
        final_ptr = (void *)(((intptr_t) ptr << 16) >> 16);
    }
    
    /* Call recursively */
    fprintf(stderr,"INFO Free_hook %p (%p)\n", final_ptr, ptr);
    __libc_free(final_ptr);

    /* Restore our own hooks */
    malloc_hook_active = 1;
    realloc_hook_active = 1;
    free_hook_active = 1;
}

static void*
dw_realloc_hook (void *ptr, size_t size)
{
    void *result, *final_result, *final_ptr;
    
    /* Restore all old hooks */
    malloc_hook_active = 0;
    realloc_hook_active = 0;
    free_hook_active = 0;

    long taint = ((long)ptr & 0xFFFF000000000000) / 0x1000000000000;
    long index = taint-1;
    final_ptr = (void *)(((intptr_t) ptr << 16) >> 16);

    if(taint == 0) final_result = result = __libc_realloc(final_ptr,size);
    
    else if(index < 0 || index > malloc_metadata_size - 1) {
        fprintf(stderr, "Invalid taint value %lu\n", taint);
    }
    
    else if(malloc_metadata[index].status == -2) {
        void *addr = malloc_metadata[index].base_addr;
        size_t old_size = malloc_metadata[index].size;
        if(addr != final_ptr) fprintf(stderr, "Not freeing the original address, %p in %p + %lu\n", final_ptr, addr, old_size); 
        /* Call recursively with untainted address*/
        result = realloc(final_ptr,size);
        malloc_metadata[index].base_addr = result;
        malloc_metadata[index].size = size;
        final_result = (void *)(((uintptr_t)result) | ((uintptr_t)taint << 48));    
    }

    else {
        final_result = result = __libc_realloc(final_ptr,size);
    }
    
    fprintf(stderr,"INFO Realloc_hook %p (%p) to %p (%p)\n", final_ptr, ptr, result, final_result);    

    /* Restore our own hooks */
    malloc_hook_active = 1;
    realloc_hook_active = 1;
    free_hook_active = 1;

    return final_result;
}

void*
malloc (size_t size)
{
        void *ret;
        // fprintf(stderr,"DDW: Malloc called by %d, hook %d, adr hook %p\n", gettid(), malloc_hook_active, &malloc_hook_active);
	if (malloc_hook_active && head != -1 && size >= min_taint_size && size <= max_taint_size && getpid() != cpid) ret = dw_malloc_hook(size);
	else {
	    ret = __libc_malloc(size);
	    fprintf(stderr,"INFO Malloc %p, size %lu, hook active %d, object list head %d, pid %d\n", ret, size, malloc_hook_active, head, getpid());
	}
	return ret;
}

void*
realloc (void *ptr, size_t size)
{
        void *ret;
        // fprintf(stderr,"DDW: Realloc called %d, hook %d, adr hook %p\n", gettid(), realloc_hook_active, &realloc_hook_active);
	if (realloc_hook_active && getpid() != cpid) ret = dw_realloc_hook(ptr, size);
	else {
	    ret = __libc_realloc(ptr, size);
	    fprintf(stderr,"INFO Realloc %p, size %lu\n", ret, size);
	}
        return ret;
}

void
free (void *ptr)
{
	if (free_hook_active && getpid() != cpid)
		return dw_free_hook(ptr);
	if(UNTAINT(ptr) != ptr) fprintf(stderr, "Tainted pointer returned to free\n");
        fprintf(stderr,"INFO Free %p\n", ptr);
	return __libc_free(ptr);
}

