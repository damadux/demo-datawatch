// You need to enable ptrace, and probably allow core dumps and disable ASLR for debugging
// systemctl disable apport.service
// sysctl -w kernel.core_pattern=core
// sysctl -w kernel.yama.ptrace_scope=0
// setarch `uname -m` -R $SHELL

// Try with a single instrumented object and see if control similarly affected (size = 65)
// Trace with lttng to check system calls and their return code
// Trace with intel-pt to see where execution diverges, recompile with debugging?
// Does malloc hooks work better
// libcapstone with pointer_method 5

// Works with mmap alloc/protect, with and without using capstone
// Works with ./simple with tainted pointers but not with tar
//    We can detect system calls with tainted pointers
//    Cannot overwrite some system calls issued from libc
//    siginfo.si_addr is 0 for tainted pointers but not for malloc memory, why?
//    tar core dumps without any problematic system call, check how accesses differ?
//
// https://chromium.googlesource.com/chromiumos/docs/+/master/constants/syscalls.md
// https://faculty.nps.edu/cseagle/assembly/sys_call.html

#define _GNU_SOURCE

#include <malloc.h>
#include <string.h>
#include <wchar.h>
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
#include <linux/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <errno.h>
#include <sched.h>
#include <limits.h>
#include <sys/mman.h>

#include <execinfo.h>
#include <unistd.h>
#include <fcntl.h>
#include <linux/openat2.h>
#include <stdarg.h>
#include <dlfcn.h>
#include <sys/vfs.h>
#include <dirent.h>

enum dw_log_level {ERROR, WARNING, INFO, DEBUG};

char* dw_log_level_name[] = {"ERROR", "WARNING", "INFO", "DEBUG"};

enum dw_log_category_name {MALLOC, FREE, SIGNAL, SYSCALL, WRAPPER, THREADS, OTHER};

struct dw_log_category {
    char *name;
    int active;
    int level;
};

struct dw_log_category dw_log_categories[] = {{"malloc", 0, 2}, {"free", 0, 2}, {"signal", 0, 2}, {"syscall", 0, 2}, {"wrapper", 0, 2}, {"threads", 0, 2}, {"other", 0, 2}};

__attribute__((unused))
static void dwlog(enum dw_log_category_name topic, enum dw_log_level level, const char *fmt, ...) {
    if(dw_log_categories[topic].active == 0 || dw_log_categories[topic].level > level) return; 
    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
}

extern void *__libc_malloc(size_t size);
extern void __libc_free(void *ptr);
extern void *__libc_calloc(size_t nmemb, size_t size);
extern void *__libc_realloc(void *ptr, size_t size);
extern void *__libc_memalign(size_t alignment, size_t size);

// extern void* (*__malloc_hook)(size_t size, const void *caller);
// extern void* (*__realloc_hook)(void *ptr, size_t size, const void *caller);
// extern void (*__free_hook)(void *ptr, const void *caller);
// extern void* (*__memalign_hook)(size_t alignment, size_t size, const void *caller);
//
// static void* (*real_malloc)(size_t size, const void *caller);
// static void* (*real_realloc)(void *ptr, size_t size, const void *caller);
// static void (*real_free)(void *ptr, const void *caller);
// static void* (*real_memalign)(size_t alignment, size_t size, const void *caller);
//
// static void* malloc_wrap(size_t size, const void *caller);
// static void* realloc_wrap(void *ptr, size_t size, const void *caller);
// static void free_wrap(void *ptr, const void *caller);
// static void* memalign_wrap(size_t alignment, size_t size, const void *caller);

void *simple_chunk = NULL;
void *simple_chunk_cursor;
size_t simple_chunk_size = 65536;

void*
simple_malloc (size_t size) {
    if(simple_chunk == NULL) {
        simple_chunk = mmap(NULL, simple_chunk_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, 0, 0);
        simple_chunk_cursor = simple_chunk;
    }

    simple_chunk_cursor += sizeof(size_t);

    size_t rest = ((long long unsigned)simple_chunk_cursor) & 0x3f;
    if(rest != 0) simple_chunk_cursor = simple_chunk_cursor + 64 - rest;
    void* ret = simple_chunk_cursor;

    size_t* header = simple_chunk_cursor - sizeof(size_t);
    *header = size;
    simple_chunk_cursor += size;

    fprintf(stderr,"INFO Malloc simple %p, size %lu\n", ret, size);
    
    if(simple_chunk_cursor >= simple_chunk + simple_chunk_size) {
        fprintf(stderr, "ERROR Simple malloc exhausted\n");
        abort();
    }
    return ret;
}

void
simple_free (void *ptr)
{
    fprintf(stderr,"INFO Free simple %p\n", ptr);
    // For now we do not bother recycling
}

static void*
simple_memalign(size_t alignment, size_t size)
{
    if(alignment > 64) fprintf(stderr, "Error, cannot simple memalign alignment %lu, size %lu\n", alignment, size);
    return simple_malloc(size);
}

static int
simple_check_size(void *ptr)
{
    if(ptr < (simple_chunk + 64) || ptr >= (simple_chunk + simple_chunk_size)) {
        fprintf(stderr, "ERROR get size of non simple malloc pointer %p\n", ptr);
        return -1;
    }
    size_t* header = (size_t *)(ptr - sizeof(size_t));
    int ret = *header;
    return ret;
}

static char* syscall_names[] = {
"read", "write", "open", "close", "stat", "fstat", "lstat", "poll", "lseek", "mmap", "mprotect", "munmap", "brk", "rt_sigaction", 
"rt_sigprocmask", "rt_sigreturn", "ioctl", "pread64", "pwrite64", "readv", "writev", "access", "pipe", "select", "sched_yield", 
"mremap", "msync", "mincore", "madvise", "shmget", "shmat", "shmctl", "dup", "dup2", "pause", "nanosleep", "getitimer", "alarm", 
"setitimer", "getpid", "sendfile", "socket", "connect", "accept", "sendto", "recvfrom", "sendmsg", "recvmsg", "shutdown", "bind", 
"listen", "getsockname", "getpeername", "socketpair", "setsockopt", "getsockopt", "clone", "fork", "vfork", "execve", "exit", 
"wait4", "kill", "uname", "semget", "semop", "semctl", "shmdt", "msgget", "msgsnd", "msgrcv", "msgctl", "fcntl", "flock", 
"fsync", "fdatasync", "truncate", "ftruncate", "getdents", "getcwd", "chdir", "fchdir", "rename", "mkdir", "rmdir", "creat", 
"link", "unlink", "symlink", "readlink", "chmod", "fchmod", "chown", "fchown", "lchown", "umask", "gettimeofday", "getrlimit", 
"getrusage", "sysinfo", "times", "ptrace", "getuid", "syslog", "getgid", "setuid", "setgid", "geteuid", "getegid", "setpgid", 
"getppid", "getpgrp", "setsid", "setreuid", "setregid", "getgroups", "setgroups", "setresuid", "getresuid", "setresgid", 
"getresgid", "getpgid", "setfsuid", "setfsgid", "getsid", "capget", "capset", "rt_sigpending", "rt_sigtimedwait", 
"rt_sigqueueinfo", "rt_sigsuspend", "sigaltstack", "utime", "mknod", "uselib", "personality", "ustat", "statfs", "fstatfs", 
"sysfs", "getpriority", "setpriority", "sched_setparam", "sched_getparam", "sched_setscheduler", "sched_getscheduler", 
"sched_get_priority_max", "sched_get_priority_min", "sched_rr_get_interval", "mlock", "munlock", "mlockall", "munlockall", 
"vhangup", "modify_ldt", "pivot_root", "_sysctl", "prctl", "arch_prctl", "adjtimex", "setrlimit", "chroot", "sync", "acct", 
"settimeofday", "mount", "umount2", "swapon", "swapoff", "reboot", "sethostname", "setdomainname", "iopl", "ioperm", 
"create_module", "init_module", "delete_module", "get_kernel_syms", "query_module", "quotactl", "nfsservctl", "getpmsg", 
"putpmsg", "afs_syscall", "tuxcall", "security", "gettid", "readahead", "setxattr", "lsetxattr", "fsetxattr", "getxattr", 
"lgetxattr", "fgetxattr", "listxattr", "llistxattr", "flistxattr", "removexattr", "lremovexattr", "fremovexattr", "tkill", 
"time", "futex", "sched_setaffinity", "sched_getaffinity", "set_thread_area", "io_setup", "io_destroy", "io_getevents", 
"io_submit", "io_cancel", "get_thread_area", "lookup_dcookie", "epoll_create", "epoll_ctl_old", "epoll_wait_old", 
"remap_file_pages", "getdents64", "set_tid_address", "restart_syscall", "semtimedop", "fadvise64", "timer_create", 
"timer_settime", "timer_gettime", "timer_getoverrun", "timer_delete", "clock_settime", "clock_gettime", "clock_getres", 
"clock_nanosleep", "exit_group", "epoll_wait", "epoll_ctl", "tgkill", "utimes", "vserver", "mbind", "set_mempolicy", 
"get_mempolicy", "mq_open", "mq_unlink", "mq_timedsend", "mq_timedreceive", "mq_notify", "mq_getsetattr", "kexec_load", 
"waitid", "add_key", "request_key", "keyctl", "ioprio_set", "ioprio_get", "inotify_init", "inotify_add_watch", 
"inotify_rm_watch", "migrate_pages", "openat", "mkdirat", "mknodat", "fchownat", "futimesat", "newfstatat", "unlinkat", 
"renameat", "linkat", "symlinkat", "readlinkat", "fchmodat", "faccessat", "pselect6", "ppoll", "unshare", "set_robust_list", 
"get_robust_list", "splice", "tee", "sync_file_range", "vmsplice", "move_pages", "utimensat", "epoll_pwait", "signalfd", 
"timerfd_create", "eventfd", "fallocate", "timerfd_settime", "timerfd_gettime", "accept4", "signalfd4", "eventfd2", 
"epoll_create1", "dup3", "pipe2", "inotify_init1", "preadv", "pwritev", "rt_tgsigqueueinfo", "perf_event_open", "recvmmsg", 
"fanotify_init", "fanotify_mark", "prlimit64", "name_to_handle_at", "open_by_handle_at", "clock_adjtime", "syncfs", 
"sendmmsg", "setns", "getcpu", "process_vm_readv", "process_vm_writev", "kcmp", "finit_module"};

// Intercept common system calls and libc utility functions to check access (not done yet)
// and remove the taint from pointers. This is essential for system calls because otherwise they will fail.
// It is useful for utility functions as it can simplify the access check (a single one instead of multiple ones)
// and avoid some functions that may perform tricky pointer arithmetic (e.g. memcpy / memmove

void *dlsym_check(void *restrict handle, const char *restrict symbol) {
    void *ret = dlsym(handle, symbol);
    if(ret == NULL) fprintf(stderr, "Symbol %s not found!\n", symbol);
    return ret;
}

// Declare all the pointers to the original libc functions

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

static int (*libc_bcmp)(const void *s1, const void *s2, size_t n);
static void (*libc_bcopy)(const void *src, void *dest, size_t n);
static void (*libc_bzero)(void *s, size_t n);
static void* (*libc_memccpy)(void *dest, const void *src, int c, size_t n);
static void* (*libc_memchr)(const void *s, int c, size_t n);
static int (*libc_memcmp)(const void *s1, const void *s2, size_t n);
static void* (*libc_memcpy)(void *dest, const void *src, size_t n);
static void* (*libc_memfrob)(void *s, size_t n);
static void* (*libc_memmem)(const void *haystack, size_t haystacklen, const void *needle, size_t needlelen);
static void* (*libc_memmove)(void *dest, const void *src, size_t n);
static void* (*libc_mempcpy)(void *restrict dest, const void *restrict src, size_t n);
static void* (*libc_memset)(void *s, int c, size_t n);
static char* (*libc_strcpy)(char *restrict dest, const char *src);
static char* (*libc_strncpy)(char *restrict dest, const char *restrict src, size_t n);
static wchar_t* (*libc_wmemmove)(wchar_t *dest, const wchar_t *src, size_t n);
static wchar_t* (*libc_wmempcpy)(wchar_t *restrict dest, const wchar_t *restrict src, size_t n);
static wchar_t* (*libc_wmemcpy)(wchar_t *restrict dest, const wchar_t *restrict src, size_t n);
static char* (*libc_gettext)(const char * msgid);
static char* (*libc_dgettext)(const char * domainname, const char * msgid);
static char* (*libc_dcgettext)(const char * domainname, const char * msgid, int category);

// Get the address for all the wrapped libc functions. Some of these functions may get called
// very early therefore we do check for initialization right before use with the iss() macro.

static int init_stubs = 0;
static int in_syscall = 0;
#define sin() in_syscall++; if(!init_stubs) init_syscall_stubs()
#define sout() in_syscall--

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

    libc_bcmp = dlsym_check(RTLD_NEXT, "bcmp");
    libc_bcopy = dlsym_check(RTLD_NEXT, "bcopy");
    libc_bzero = dlsym_check(RTLD_NEXT, "bzero");
    libc_memccpy = dlsym_check(RTLD_NEXT, "memccpy");
    libc_memchr = dlsym_check(RTLD_NEXT, "memchr");
    libc_memcmp = dlsym_check(RTLD_NEXT, "memcmp");
    libc_memcpy = dlsym_check(RTLD_NEXT, "memcpy");
    libc_memfrob = dlsym_check(RTLD_NEXT, "memfrob");
    libc_memmem = dlsym_check(RTLD_NEXT, "memmem");
    libc_memmove = dlsym_check(RTLD_NEXT, "memmove");
    libc_mempcpy = dlsym_check(RTLD_NEXT, "mempcpy");
    libc_memset = dlsym_check(RTLD_NEXT, "memset");
    libc_strcpy = dlsym_check(RTLD_NEXT, "strcpy");
    libc_strncpy = dlsym_check(RTLD_NEXT, "strncpy");
    libc_wmemmove = dlsym_check(RTLD_NEXT, "wmemmove");
    libc_wmempcpy = dlsym_check(RTLD_NEXT, "wmempcpy");
    libc_wmemcpy = dlsym_check(RTLD_NEXT, "wmemcpy");
    libc_gettext = dlsym_check(RTLD_NEXT, "gettext");
    libc_dgettext = dlsym_check(RTLD_NEXT, "dgettext ");
    libc_dcgettext = dlsym_check(RTLD_NEXT, "dcgettext");

    init_stubs = 1;
}

// UNTAINT or UNPROTECT!?!
#define GETTAINT(adr) ((char *)(((long long unsigned)(adr)) >> 48))
#define SETTAINT(adr, taint) ((char *)(((long long unsigned)0x0000ffffffffffff & (long long unsigned)(adr)) | (((long long unsigned)(taint)) << 48)))
#define UNTAINT(adr) ((char *)((long long unsigned)0x0000ffffffffffff & (long long unsigned)(adr)))
#define RETAINT(adr, taint) ((char *)(((long long unsigned)0x0000ffffffffffff & (long long unsigned)(adr)) | ((long long unsigned)0xffff000000000000 & (long long unsigned)(taint))))

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

struct object_id *malloc_metadata;  // CHECK volatile
static int malloc_metadata_size = 356;

// Alternative method to check pointers. Instead of a taint, the allocated area is protected from any access.
// A SIGSEGV is thus generated upon access. The access is checked, the memory protection is put to READ/WRITE,
// the access instruction is singlestep, and the non access protection is put back.

struct mmap_pointer_table {
    void *base_addr;
    size_t size;
    void *end;
    int status;
};

// 3 taint pointers, 2 noop taint, 5 mprotect mmaped areas, 4 noop mprotect
static unsigned address_method = 0;
static long unsigned pointer_method = 3;
enum __ptrace_request tracee_continue = PTRACE_CONT;

static struct mmap_pointer_table *mmap_metadata;
static int mmap_metadata_size = 1000;
static int mmap_oid_last;

static void 
mmap_pointer_module_init() {
    mmap_metadata = malloc(mmap_metadata_size * sizeof(struct mmap_pointer_table));
    mmap_oid_last = 0;
}

static int
mmap_check_size(const void *addr) {
    for(int i = 0; i < mmap_oid_last; i++) {
        if(addr >= mmap_metadata[i].base_addr && addr < mmap_metadata[i].end) {
            return mmap_metadata[i].size;
        }
    }
    return -1;
}

static int
mmap_pointer_check_access(const void *addr) {
    for(int i = 0; i < mmap_oid_last; i++) {
        if(addr >= mmap_metadata[i].base_addr && addr < mmap_metadata[i].end) {
            if(pointer_method == 5) {
                in_syscall++;
                mprotect(mmap_metadata[i].base_addr, mmap_metadata[i].size, PROT_READ | PROT_WRITE);
                in_syscall--;
                fprintf(stderr, "Unprotect %p (%p)\n", mmap_metadata[i].base_addr, addr);
            }
            return 1;
        }
    }
    return 0;
}

static void
mmap_pointer_resume_access(const void *addr) {
    for(int i = 0; i < mmap_oid_last; i++) {
        if(addr >= mmap_metadata[i].base_addr && addr < mmap_metadata[i].end) {
            if(pointer_method == 5) {
                in_syscall++;
                mprotect(mmap_metadata[i].base_addr, mmap_metadata[i].size, PROT_NONE);
                in_syscall--;
                fprintf(stderr, "Protect %p (%p)\n", mmap_metadata[i].base_addr, addr);
            }
            return;
        }
    }
}

static void
mmap_pointer_unprotect_all() {
    for(int i = 0; i < mmap_oid_last; i++) {
        in_syscall++;
        mprotect(mmap_metadata[i].base_addr, mmap_metadata[i].size, PROT_READ | PROT_WRITE);
        in_syscall--;
        fprintf(stderr, "Unprotect %p\n", mmap_metadata[i].base_addr);

    }
}

static void
mmap_pointer_reprotect_all() {
    for(int i = 0; i < mmap_oid_last; i++) {
        in_syscall++;
        mprotect(mmap_metadata[i].base_addr, mmap_metadata[i].size, PROT_NONE);
        in_syscall--;
        fprintf(stderr, "Protect %p\n", mmap_metadata[i].base_addr);

    }
}

static void *
mmap_pointer_malloc_hook(size_t size) {
    size_t real_size = (size / 4096) * 4096;
    if((size % 4096) > 0) real_size += 4096;

    void* addr;
    if(pointer_method == 5) addr = mmap(NULL, size, PROT_NONE, MAP_SHARED | MAP_ANONYMOUS, 0, 0);
    else  addr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, 0, 0);
    mmap_metadata[mmap_oid_last].base_addr = addr;
    mmap_metadata[mmap_oid_last].size = size;
    mmap_metadata[mmap_oid_last].status = 0;
    mmap_metadata[mmap_oid_last].end = addr + real_size;
    mmap_oid_last++;
    if(mmap_oid_last >= mmap_metadata_size) fprintf(stderr, "Warning, last mmap pointer entry\n");
    fprintf(stderr,"INFO Malloc mmap hook %p, size %lu (%lu)\n", addr, size, real_size);    
    return addr;
}

static void
mmap_pointer_free_hook (void *ptr) {
    for(int i = 0; i < mmap_metadata_size; i++) {
        if(ptr >= mmap_metadata[i].base_addr && ptr < mmap_metadata[i].end) {
            munmap(mmap_metadata[i].base_addr, mmap_metadata[i].size);
            mmap_oid_last--;
            if(i < mmap_oid_last && mmap_oid_last > 0) mmap_metadata[i] = mmap_metadata[mmap_oid_last];
            fprintf(stderr,"INFO Free mmap hook %p\n", ptr);
            return;
        }
    }
    fprintf(stderr,"INFO Free %p\n", ptr);
    return __libc_free(ptr);    
}


static void *
mmap_pointer_memalign_hook(size_t alignment, size_t size) {
    if(alignment > 4096) fprintf(stderr,"Error Memalign mmap alignment too large %lu\n", alignment);    
    return mmap_pointer_malloc_hook(size);
}

static inline void *unprotect(const void *addr) {
    if(pointer_method & 4) { mmap_pointer_check_access(addr); return (void *)addr; }
    else return UNTAINT(addr);
}

static inline void reprotect(const void *addr) {
    if(pointer_method & 4) mmap_pointer_resume_access(addr);
}

static inline int is_protected(const void *addr) {
    if(pointer_method & 4)
        for(int i = 0; i < mmap_oid_last; i++) {
        if(addr >= mmap_metadata[i].base_addr && addr < mmap_metadata[i].end) {
            if(pointer_method == 5) mprotect(mmap_metadata[i].base_addr, mmap_metadata[i].size, PROT_READ | PROT_WRITE);
            return 1;
        }
        return 0;
    } else {
        long unsigned taint = (long long unsigned) GETTAINT(addr);
        long index = taint - 1;
        if(taint != 0) {
            if(index < 0 || index > malloc_metadata_size - 1) return -1;
            return 1;
        }
    }
    return 0;
}

// The replacements for libc functions for now simply remove the taint before calling
// the replaced functions. In some cases, the taint must be reapplied. For instance,
// the memccpy function copies a string to a certain character then returns a pointer to
// that character. This pointer may be derived from a tainted pointer and the taint must be
// carried to it from the dest pointer.

// Open can take 2 or 3 arguments, we handle it just like glibc does it internally.

int open(const char *pathname, int flags, ...) { 
    sin(); 
    mode_t mode = 0; 
    if(__OPEN_NEEDS_MODE(flags)) {
        va_list arg; 
        va_start(arg, flags); 
        mode = va_arg(arg, mode_t);
        va_end(arg);
    }
    int ret = libc_open(unprotect((void *)pathname), flags, mode);
    reprotect((void *)pathname); sout(); return ret;
}

int openat(int dirfd, const char *pathname, int flags, ...) { 
    sin(); 
    mode_t mode = 0; 
    if(__OPEN_NEEDS_MODE(flags)) {
        va_list arg; 
        va_start(arg, flags); 
        mode = va_arg(arg, mode_t);
        va_end(arg);
    }
    int ret = libc_openat(dirfd, unprotect((void *)pathname), flags, mode);
    reprotect((void *)pathname); sout(); return ret;
}

// int openat2(int dirfd, const char *pathname, const struct open_how *how, size_t size) { sin(); return libc_openat2(dirfd, unprotect(pathname), how, size); }
int creat(const char *pathname, mode_t mode) { sin(); int ret = libc_creat(unprotect((void *)pathname), mode); reprotect((void *)pathname); sout(); return ret; }
int access(const char *pathname, int mode) { sin(); int ret = libc_access(unprotect((void *)pathname), mode); reprotect((void *)pathname); sout(); return ret; }
char *getcwd(char *buf, size_t size) { sin(); char *ret = libc_getcwd(unprotect((void *)buf), size); reprotect((void *)buf); sout(); if(ret == UNTAINT(buf)) return buf; return ret; }
ssize_t getrandom(void *buf, size_t buflen, unsigned int flags) { sin(); ssize_t ret = libc_getrandom(unprotect(buf), buflen, flags); reprotect(buf); sout(); return ret; }
int stat(const char *restrict pathname, struct stat *restrict statbuf) { sin(); int ret = libc_stat(unprotect((void *)pathname), (struct stat *)unprotect((void *)statbuf)); reprotect((void *)pathname); reprotect((void *)statbuf); sout(); return ret; }
int fstat(int fd, struct stat *statbuf) { sin(); int ret = libc_fstat(fd, (struct stat *)unprotect(statbuf)); reprotect(statbuf); sout(); return ret; }
int lstat(const char *restrict pathname, struct stat *restrict statbuf) { sin(); int ret = libc_lstat(unprotect((void *)pathname), (struct stat *)unprotect((void *)statbuf)); reprotect((void *)pathname); reprotect((void *)statbuf); sout(); return ret; }
int fstatat(int dirfd, const char *restrict pathname, struct stat *restrict statbuf, int flags) { sin(); int ret = libc_fstatat(dirfd, unprotect((void *)pathname), (struct stat *)unprotect((void *)statbuf), flags); reprotect((void *)pathname); reprotect((void *)statbuf); sout(); return ret; }
ssize_t pread(int fd, void *buf, size_t count, off_t offset) { sin(); ssize_t ret = libc_pread(fd, unprotect(buf), count, offset); reprotect(buf); sout(); return ret; }
ssize_t pwrite(int fd, const void *buf, size_t count, off_t offset) { sin(); ssize_t ret = libc_pwrite(fd, (const void *)unprotect(buf), count, offset); reprotect(buf); sout(); return ret; }
ssize_t read(int fd, void *buf, size_t count) { sin(); ssize_t ret = libc_read(fd, unprotect(buf), count); reprotect(buf); sout(); return ret; }
ssize_t write(int fd, const void *buf, size_t count) { sin(); ssize_t ret = libc_write(fd, (const void *)unprotect(buf), count); reprotect(buf); sout(); return ret; }
int statfs(const char *path, struct statfs *buf) { sin(); int ret = libc_statfs(unprotect((void *)path), (struct statfs *)unprotect((void *)buf)); reprotect((void *)path); reprotect((void *)buf); sout(); return ret; }
int fstatfs(int fd, struct statfs *buf) { sin(); int ret = libc_fstatfs(fd, (struct statfs *)unprotect((void *)buf)); reprotect((void *)buf); sout(); return ret; }
ssize_t getdents64(int fd, void *dirp, size_t count) { sin(); ssize_t ret = libc_getdents64(fd, unprotect(dirp), count); reprotect(dirp); sout(); return ret; }

int bcmp(const void *s1, const void *s2, size_t n) { sin(); int ret = libc_bcmp((const void *)unprotect(s1), (const void *)unprotect(s2), n); reprotect(s1); reprotect(s2); sout(); return ret; }
void bcopy(const void *src, void *dest, size_t n) { sin(); libc_bcopy((const void *)unprotect(src), (void *)unprotect(dest), n); reprotect(src); reprotect(dest); }
void bzero(void *s, size_t n) { sin(); libc_bzero((void *)unprotect(s), n); reprotect(s); }

void *memccpy(void *dest, const void *src, int c, size_t n) { 
    sin(); 
    void *ret = libc_memccpy((void *)unprotect(dest), (const void *)unprotect(src), c, n);
    reprotect(dest);
    reprotect(src);
    sout();
    if(ret == NULL) return ret;
    return (void *)RETAINT(ret, dest);
}

void *memchr(const void *s, int c, size_t n) { 
    sin(); 
    void *ret = libc_memchr((const void *)unprotect(s), c, n);
    reprotect(s);
    sout();
    if(ret == NULL) return ret;
    return (void *)RETAINT(ret, s);
}

int memcmp(const void *s1, const void *s2, size_t n) { sin(); int ret = libc_memcmp((const void *)unprotect(s1), (const void *)unprotect(s2), n); reprotect(s1); reprotect(s2); sout(); return ret; }
void *memcpy(void *dest, const void *src, size_t n) { sin(); fprintf(stderr, "Memcpy wrap \n"); libc_memcpy((void *)unprotect(dest), (const void *)unprotect(src), n); reprotect(dest); reprotect(src); sout(); return dest; }
// void *memfrob(void *s, size_t n) { sin(); return libc_memfrob(void *s, size_t n); }

void *memmem(const void *haystack, size_t haystacklen, const void *needle, size_t needlelen) { 
    sin();
    void *ret = libc_memmem((const void *)unprotect(haystack), haystacklen, (const void *)unprotect(needle), needlelen); 
    reprotect(haystack); reprotect(needle);
    sout();
    if(ret == NULL) return ret;
    return (void *)RETAINT(ret, haystack);
}

void *memmove(void *dest, const void *src, size_t n) { sin(); libc_memmove((void *)unprotect(dest), (void *)unprotect(src), n); reprotect(dest); reprotect(src); sout(); return dest; }
void *mempcpy(void *restrict dest, const void *restrict src, size_t n) { sin(); libc_mempcpy((void *)unprotect(dest), (void *)unprotect(src), n); reprotect(dest); reprotect(src); sout(); return dest; }
void *memset(void *s, int c, size_t n) { sin(); libc_memset((void *)unprotect(s), c, n); reprotect(s); sout(); return s; }
char *strcpy(char *restrict dest, const char *src) { sin(); libc_strcpy(unprotect(dest), unprotect(src)); reprotect(dest); reprotect(src); sout(); return dest;}
char *strncpy(char *restrict dest, const char *restrict src, size_t n) { sin(); libc_strncpy(unprotect(dest), unprotect(src), n); reprotect(dest); reprotect(src); sout(); return dest; }
wchar_t *wmemmove(wchar_t *dest, const wchar_t *src, size_t n) { sin(); libc_wmemmove((wchar_t *)unprotect(dest), (wchar_t *)unprotect(src), n); reprotect(dest); reprotect(src); sout(); return dest; }

wchar_t *wmempcpy(wchar_t *restrict dest, const wchar_t *restrict src, size_t n) { 
    sin(); 
    wchar_t *ret = libc_wmempcpy((wchar_t *)unprotect(dest), (wchar_t *)unprotect(src), n);
    reprotect(dest); reprotect(src);
    sout(); return (wchar_t *)RETAINT(ret, dest);
}

wchar_t *wmemcpy(wchar_t *restrict dest, const wchar_t *restrict src, size_t n) { sin(); libc_wmemcpy((wchar_t *)unprotect(dest), (wchar_t *)unprotect(src), n); reprotect(dest); reprotect(src); sout(); return dest; }
char *gettext (const char * msgid) { sin(); fprintf(stderr, "Gettext wrap %p\n", msgid); char *ret = libc_gettext(unprotect(msgid)); reprotect(msgid); sout(); if(ret == UNTAINT(msgid)) return (char *)msgid; else return ret; }
char *dgettext (const char * domainname, const char * msgid) { sin(); fprintf(stderr, "Dgettext wrap %p\n", msgid); char *ret = libc_dgettext (unprotect(domainname), unprotect(msgid)); reprotect(domainname); reprotect(msgid); sout(); if(ret == UNTAINT(msgid)) return (char *)msgid; else return ret; }
char *dcgettext (const char * domainname, const char * msgid, int category) { sin(); fprintf(stderr, "Dcgettext wrap %p\n", msgid); char *ret = libc_dcgettext (unprotect(domainname), unprotect(msgid), category); reprotect(domainname); reprotect(msgid); sout(); if(ret == UNTAINT(msgid)) return (char *)msgid; else return ret; }

// Registers available from ptrace GETREGS and SETREGS commands. Their names and functions to access them.

static unsigned long long get_user_reg(unsigned long reg, struct user_regs_struct *regs) {
    switch(reg) {
        case 0: return regs->r15;
        case 1: return regs->r14;
        case 2: return regs->r13;
        case 3: return regs->r12;
        case 4: return regs->rbp;
        case 5: return regs->rbx;
        case 6: return regs->r11;
        case 7: return regs->r10;
        case 8: return regs->r9;
        case 9: return regs->r8;
        case 10: return regs->rax;
        case 11: return regs->rcx;
        case 12: return regs->rdx;
        case 13: return regs->rsi;
        case 14: return regs->rdi;
        case 15: return regs->orig_rax;
        case 16: return regs->rip;
        case 17: return regs->cs;
        case 18: return regs->eflags;
        case 19: return regs->rsp;
        case 20: return regs->ss;
        case 21: return regs->fs_base;
        case 22: return regs->gs_base;
        case 23: return regs->ds;
        case 24: return regs->es;
        case 25: return regs->fs;
        case 26: return regs->gs;
        default: return 0;
    }
};

char *user_regs_name[] = {
  "r15",
  "r14",
  "r13",
  "r12",
  "rbp",
  "rbx",
  "r11",
  "r10",
  "r9",
  "r8",
  "rax",
  "rcx",
  "rdx",
  "rsi",
  "rdi",
  "orig_rax",
  "rip",
  "cs",
  "eflags",
  "rsp",
  "ss",
  "fs_base",
  "gs_base",
  "ds",
  "es",
  "fs",
  "gs"
};

static void compare_user_regs(struct user_regs_struct *old_regs, struct user_regs_struct *new_regs) {
    long long unsigned old_value, new_value;
    for(int i = 0; i < 27; i++) {
        old_value = get_user_reg(i, old_regs);
        new_value = get_user_reg(i, new_regs);
        if(new_value != old_value) fprintf(stderr, "Register %s differs 0x%llx, 0x%llx\n", user_regs_name[i], old_value, new_value);
    }
}

/* Names and values for registers used in the Capstone disassembly library

typedef enum x86_reg {
        X86_REG_INVALID = 0,
        X86_REG_AH, X86_REG_AL, X86_REG_AX, X86_REG_BH, X86_REG_BL, // 1-5
        X86_REG_BP, X86_REG_BPL, X86_REG_BX, X86_REG_CH, X86_REG_CL, // 6-10
        X86_REG_CS, X86_REG_CX, X86_REG_DH, X86_REG_DI, X86_REG_DIL, // 11-15
        X86_REG_DL, X86_REG_DS, X86_REG_DX, X86_REG_EAX, X86_REG_EBP, // 16-20
        X86_REG_EBX, X86_REG_ECX, X86_REG_EDI, X86_REG_EDX, X86_REG_EFLAGS, // 21-25
        X86_REG_EIP, X86_REG_EIZ, X86_REG_ES, X86_REG_ESI, X86_REG_ESP, // 26-30
        X86_REG_FPSW, X86_REG_FS, X86_REG_GS, X86_REG_IP, X86_REG_RAX, // 31-35
        X86_REG_RBP, X86_REG_RBX, X86_REG_RCX, X86_REG_RDI, X86_REG_RDX, // 36-40
        X86_REG_RIP, X86_REG_RIZ, X86_REG_RSI, X86_REG_RSP, X86_REG_SI, // 41-45
        X86_REG_SIL, X86_REG_SP, X86_REG_SPL, X86_REG_SS, X86_REG_CR0, // 46-50
        X86_REG_CR1, X86_REG_CR2, X86_REG_CR3, X86_REG_CR4, X86_REG_CR5, // 51-55
        X86_REG_CR6, X86_REG_CR7, X86_REG_CR8, X86_REG_CR9, X86_REG_CR10, // 56-60
        X86_REG_CR11, X86_REG_CR12, X86_REG_CR13, X86_REG_CR14, X86_REG_CR15, // 61-65
        X86_REG_DR0, X86_REG_DR1, X86_REG_DR2, X86_REG_DR3, X86_REG_DR4, // 66-70
        X86_REG_DR5, X86_REG_DR6, X86_REG_DR7, X86_REG_DR8, X86_REG_DR9, // 71-75
        X86_REG_DR10, X86_REG_DR11, X86_REG_DR12, X86_REG_DR13, X86_REG_DR14, // 76-80
        X86_REG_DR15, X86_REG_FP0, X86_REG_FP1, X86_REG_FP2, X86_REG_FP3, // 81-85
        X86_REG_FP4, X86_REG_FP5, X86_REG_FP6, X86_REG_FP7, X86_REG_K0, // 86-90
        X86_REG_K1, X86_REG_K2, X86_REG_K3, X86_REG_K4, X86_REG_K5, // 91-95
        X86_REG_K6, X86_REG_K7, X86_REG_MM0, X86_REG_MM1, X86_REG_MM2, // 96-100
        X86_REG_MM3, X86_REG_MM4, X86_REG_MM5, X86_REG_MM6, X86_REG_MM7, // 101-105
        X86_REG_R8, X86_REG_R9, X86_REG_R10, X86_REG_R11, X86_REG_R12, // 106-110
        X86_REG_R13, X86_REG_R14, X86_REG_R15, X86_REG_ST0, X86_REG_ST1, // 111-115
        X86_REG_ST2, X86_REG_ST3, X86_REG_ST4, X86_REG_ST5, X86_REG_ST6, // 116-120
        X86_REG_ST7, X86_REG_XMM0, X86_REG_XMM1, X86_REG_XMM2, X86_REG_XMM3, // 121-125
        X86_REG_XMM4, X86_REG_XMM5, X86_REG_XMM6, X86_REG_XMM7, X86_REG_XMM8, // 125-130
        X86_REG_XMM9, X86_REG_XMM10, X86_REG_XMM11, X86_REG_XMM12, X86_REG_XMM13, // 131-135
        X86_REG_XMM14, X86_REG_XMM15, X86_REG_XMM16, X86_REG_XMM17, X86_REG_XMM18, // 136-140
        X86_REG_XMM19, X86_REG_XMM20, X86_REG_XMM21, X86_REG_XMM22, X86_REG_XMM23, // 141-145
        X86_REG_XMM24, X86_REG_XMM25, X86_REG_XMM26, X86_REG_XMM27, X86_REG_XMM28, // 146-150
        X86_REG_XMM29, X86_REG_XMM30, X86_REG_XMM31, X86_REG_YMM0, X86_REG_YMM1, // 151-155
        X86_REG_YMM2, X86_REG_YMM3, X86_REG_YMM4, X86_REG_YMM5, X86_REG_YMM6, // 156-160
        X86_REG_YMM7, X86_REG_YMM8, X86_REG_YMM9, X86_REG_YMM10, X86_REG_YMM11, // 161-165
        X86_REG_YMM12, X86_REG_YMM13, X86_REG_YMM14, X86_REG_YMM15, X86_REG_YMM16, // 166-170
        X86_REG_YMM17, X86_REG_YMM18, X86_REG_YMM19, X86_REG_YMM20, X86_REG_YMM21, // 171-175
        X86_REG_YMM22, X86_REG_YMM23, X86_REG_YMM24, X86_REG_YMM25, X86_REG_YMM26, // 176-180
        X86_REG_YMM27, X86_REG_YMM28, X86_REG_YMM29, X86_REG_YMM30, X86_REG_YMM31, // 181-185
        X86_REG_ZMM0, X86_REG_ZMM1, X86_REG_ZMM2, X86_REG_ZMM3, X86_REG_ZMM4, // 186-190
        X86_REG_ZMM5, X86_REG_ZMM6, X86_REG_ZMM7, X86_REG_ZMM8, X86_REG_ZMM9, // 191-195
        X86_REG_ZMM10, X86_REG_ZMM11, X86_REG_ZMM12, X86_REG_ZMM13, X86_REG_ZMM14, // 195-200
        X86_REG_ZMM15, X86_REG_ZMM16, X86_REG_ZMM17, X86_REG_ZMM18, X86_REG_ZMM19, // 201-205
        X86_REG_ZMM20, X86_REG_ZMM21, X86_REG_ZMM22, X86_REG_ZMM23, X86_REG_ZMM24, // 206-210
        X86_REG_ZMM25, X86_REG_ZMM26, X86_REG_ZMM27, X86_REG_ZMM28, X86_REG_ZMM29, // 211-215
        X86_REG_ZMM30, X86_REG_ZMM31, X86_REG_R8B, X86_REG_R9B, X86_REG_R10B, // 216-220
        X86_REG_R11B, X86_REG_R12B, X86_REG_R13B, X86_REG_R14B, X86_REG_R15B, // 221-225
        X86_REG_R8D, X86_REG_R9D, X86_REG_R10D, X86_REG_R11D, X86_REG_R12D, // 226-230
        X86_REG_R13D, X86_REG_R14D, X86_REG_R15D, X86_REG_R8W, X86_REG_R9W, // 231-235
        X86_REG_R10W, X86_REG_R11W, X86_REG_R12W, X86_REG_R13W, X86_REG_R14W, // 236-240
        X86_REG_R15W, X86_REG_ENDING
} x86_reg;
*/

// Functions to access the ptrace SETREGS and GETREGS registers from the Capstone library registers identifiers.

static int
get_reg(int reg, struct user_regs_struct *regs, long long unsigned *value) {
    int ret = 0;
    switch(reg) {
        case X86_REG_INVALID: *value = 0; break;
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
        default:
            fprintf(stderr, "Unhandled register %d\n", reg);
            ret = -1;
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
        default:
            fprintf(stderr, "Unhandled register %d\n", reg);
            ret = -1;
    }
    return ret;
}

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

static int malloc_hook_active = 0;
static int ppid, ptid, cpid;
static void* child_stack_start;
static void* child_stack_end;

static volatile long dw_TAG; // A constant tag to store in the top 16 bits of any new pointer
static volatile uintptr_t dw_MASK;

static int is_child() {
    void* frame = __builtin_frame_address(0);
    if(frame >= child_stack_start && frame < child_stack_end) return 1;
    return 0;
}

int head = -1;

int tracee_state = 0; // 0 initial trap, 1 syscall_entry, 2 syscall_exit

static int
child_program(void* malloc_addr) {

    fprintf(stderr,"INFO Child_program started, parent id %d, pid %d, tid %d\n", getppid(), getpid(), gettid());
    
    // Attach to "parent" thread

    int err = ptrace(PTRACE_ATTACH, ptid, NULL, NULL);
    if(err < 0) {
        fprintf(stderr,"Child_program not attached ptrace returns %d, errno %d\n", err, errno);
    } else fprintf(stderr,"INFO Child_program attached %d\n", err);
    
    int status;	
    struct user_regs_struct regs, new_regs;
    char buffer[1024];

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
        struct ptrace_syscall_info si;
        if(WIFSTOPPED(status)) {
            s = WSTOPSIG(status);
            if(s == SIGSTOP) {
                // Initial STOP, just continue
                if(tracee_state == 0) {
                    fprintf(stderr, "Initial STOP, set option and continue\n");
                    err = ptrace(PTRACE_SETOPTIONS, ptid, NULL, PTRACE_O_TRACESYSGOOD);
                    if(err < 0) fprintf(stderr, "ptrace set options failed %d\n", err);
                    tracee_state = 1;
                }
                else fprintf(stderr, "Spurious STOP\n");
                ptrace(tracee_continue,ppid,NULL,NULL);
                continue;
            } else if(s == (SIGTRAP|0x80)) {
            
                // Syscall entry
                if(tracee_state == 1) {
                    tracee_state = 2;
                    ptrace(PTRACE_GET_SYSCALL_INFO, ppid, sizeof(struct ptrace_syscall_info), &si);
                    if(si.op != PTRACE_SYSCALL_INFO_ENTRY) { fprintf(stderr, "Error, not syscall entry\n");
                    } else {
                        snprintf(buffer, 1024, "Syscall %s (0x%llx, 0x%llx, 0x%llx, 0x%llx, 0x%llx, 0x%llx) = ", syscall_names[si.entry.nr], si.entry.args[0], si.entry.args[1], si.entry.args[2], si.entry.args[3], si.entry.args[4], si.entry.args[5]);

                        if(pointer_method & 1) {
                            for(int i = 0; i < 6; i++) {
                                if(is_protected((void *)(si.entry.args[i])) == 1) {
                                    fprintf(stderr, "Error, Argument %d protected\n", i);
                                }
                            }
                            if(pointer_method == 5 && in_syscall == 0) mmap_pointer_unprotect_all();
                        }
                    }
                
                // Syscall exit
                } else if(tracee_state == 2) {
                    tracee_state = 1;
                    ptrace(PTRACE_GET_SYSCALL_INFO, ppid, sizeof(struct ptrace_syscall_info), &si);
                    if(si.op != PTRACE_SYSCALL_INFO_EXIT) { fprintf(stderr, "Error, not syscall exit\n");
                    } else {
                        fprintf(stderr, "%s%lld, %d\n", buffer, si.exit.rval, in_syscall);
                        if(pointer_method == 5 && in_syscall == 0) mmap_pointer_reprotect_all();
                    }
                }
                ptrace(tracee_continue,ppid,NULL,NULL);
                continue;
            } else if(s != SIGSEGV && s != SIGBUS) {
                fprintf(stderr, "Traced process stopped by other signal %d, continuing\n", s);
                ptrace(tracee_continue,ppid,NULL,NULL);
                continue;
            }
        }   
        else fprintf(stderr, "Traced process not exited nor stopped by a signal??\n");
       
        ptrace(PTRACE_GETREGS, ppid, NULL, &regs);
        long long unsigned addr, siginfo_addr, base_addr, index_addr, scale, displacement;
        uint64_t instr_addr = (uint64_t) regs.rip;
        const uint8_t *code = (uint8_t *) regs.rip;
        int reg = -1;
        int base_reg = -1;
        int index_reg = -1;
        int dest_reg = -1;    

        siginfo_t siginfo;
        err = ptrace(PTRACE_GETSIGINFO, ppid, 0, &siginfo);
        if(err < 0) fprintf(stderr, "Error, GETSIGINFO returned %d\n", err);
        siginfo_addr = (long long unsigned)siginfo.si_addr;
    	fprintf(stderr, "INFO Signal %d, rip = 0x%llx, si_addr = %llx, ret = %d\n", s, regs.rip, siginfo_addr, err);

        // We do not need to untaint pointers, thus we only need the offending address
        // which can be obtained with SIGINFO
        if(pointer_method != 3 && address_method == 0) {
            addr = siginfo_addr;
        } else {
            size_t sizeds = 100;
            int res_base, res_index;
    
      	    bool success = cs_disasm_iter(handle, &code , &sizeds, &instr_addr, insn);
    	    fprintf(stderr, "INFO Signal %d, disasm 0x%llx (%d, %d), 0x%lx: %s %s, (%hu)\n", s, regs.rip, success, cs_errno(handle), insn->address, insn->mnemonic, insn->op_str, insn->size);
        
            detail = insn->detail;
    	    x86 = &detail->x86;
    	    if(x86->op_count < 1) { fprintf(stderr, "Received SIGSEGV but instruction has no argument\n"); abort(); }

            // The memory address is given by base + (index * scale) + displacement
            // Check which registers are active and add them to addr and compare to singinfo_addr
    	    for (size_t i=0; i < x86->op_count; i++){
    	        switch(x86->operands[i].type) {
    	            case X86_OP_REG: 
    	                if(x86->operands[i].access & CS_AC_WRITE) dest_reg = x86->operands[i].reg;
    	                fprintf(stderr, "Register operand %lu, reg %d, access %hhu\n", i, x86->operands[i].reg, x86->operands[i].access);
    	                break;
                    case X86_OP_MEM:
                        base_reg = x86->operands[i].mem.base;
                        index_reg = x86->operands[i].mem.index;
                        res_base = get_reg(base_reg, &regs, &base_addr);
                        res_index = get_reg(index_reg, &regs, &index_addr);
                        scale = x86->operands[i].mem.scale;
                        displacement = x86->operands[i].mem.disp;
                        addr = base_addr + (index_addr * scale) + displacement;
                        if(addr != siginfo_addr) fprintf(stderr, "Error, siginfo_addr and addr disagree\n");
                        
    	                fprintf(stderr, "Memory operand %lu, segment %d, base %d (0x%llx) + (index %d (0x%llx) x scale %llx) + disp %llx = %llx, access %hhu\n", i, 
    	                    x86->operands[i].mem.segment, base_reg, base_addr, index_reg, index_addr, scale, displacement, addr, x86->operands[i].access);
                        if(res_base < 0 || res_index < 0) {
                            fprintf(stderr, "Unhandled register %d, we are doomed\n", reg);
                            abort();
                        }
                        break;
                    case X86_OP_IMM:
                        fprintf(stderr, "Immediate operand %lu, value %lu\n", i, x86->operands[i].imm);
                        break;
                    default:
                        fprintf(stderr, "Invalid operand %lu\n", i);
                        break;
                }
            }
        }
        
        if(pointer_method == 3) {

            // Check if we should take base or index as tainted register
            long unsigned taint = 0;
            long unsigned base_taint = (long long unsigned) GETTAINT(base_addr);
            long unsigned index_taint = (long long unsigned) GETTAINT(index_addr);
            long long unsigned org_addr;
            addr = (long long unsigned)UNTAINT(addr);

            if(base_taint) {
                taint = base_taint;
                reg = base_reg;
                org_addr = (long long unsigned) UNTAINT(base_addr);
                if(index_taint) fprintf(stderr, "Error, both base and index are tainted\n");
            } else if(index_taint) {
                taint = index_taint;
                reg = index_reg;
                org_addr = (long long unsigned) UNTAINT(index_addr);
                if(scale != 0) fprintf(stderr, "Error, tainted index with scale != 1\n");
            }
                
            long index = taint - 1;
            long long unsigned new_addr;

            fprintf(stderr, "INFO Addr 0x%llx, taint %lu, org_addr 0x%llx, reg %d, dest_reg %d\n", addr, taint, org_addr, reg, dest_reg);

            if(taint == 0) {
                fprintf(stderr, "SIGSEGV of unknown origin, no taint, we are doomed\n");
                abort();
            }

            if(index < 0 || index > malloc_metadata_size - 1) {
                fprintf(stderr, "Program has invalid taint\n");
                abort();
            }
	    // Bounds checking  
	    void *obj_start = malloc_metadata[index].base_addr;
	    size_t obj_size = malloc_metadata[index].size;
                
            if ((void *)addr >= obj_start && (void *)addr < (obj_start + obj_size)) {  // CHECK, we should know the number of bytes accessed
                // Bounds check succeeded, nothing to do
                // fprintf(stderr, "Bounds check successful\n");
            }
            else {
                fprintf(stderr, "Error, bounds check unsuccessful, addr 0x%llx, taint %lu, obj start %p, size %lu\n", addr, taint, obj_start, obj_size);
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
                if(s == SIGSEGV || s == SIGBUS) {
                    fprintf(stderr, "SIGSEGV of unknown origin in singlestep, we are doomed\n");
                    abort();
                }
             }

            ptrace(PTRACE_GETREGS,ppid,NULL,&new_regs);
            compare_user_regs(&regs, &new_regs);
            get_reg(reg, &new_regs, &new_addr);

            if(reg == dest_reg) {
                if(org_addr != new_addr) fprintf(stderr, "INFO Memory base register is also destination register and modified, do not retaint\n");
                else fprintf(stderr, "STRANGE Memory base register is also destination register but not modified, do not retaint\n");
            }
            else if(org_addr != new_addr) fprintf(stderr, "STRANGE Memory base register modified but should not, do not retaint\n");
            else {
                set_reg(reg, &new_regs, addr);
                ptrace(PTRACE_SETREGS,ppid,NULL,&new_regs);
            }
        }
        else {
            if(mmap_pointer_check_access((void *)addr)) {
                fprintf(stderr, "MProtected access %llx\n", addr);
                ptrace(PTRACE_SINGLESTEP,ppid,NULL,NULL);
                waitpid(ptid,&status,0);
                if(WIFEXITED(status)) break;
                if(WIFSTOPPED(status)) {
                    int s = WSTOPSIG(status);
                    if(s != SIGTRAP) {
                        fprintf(stderr, "Single step not followed by trap, %d\n", s);
                    }
                    if(s == SIGSEGV || s == SIGBUS) {
                        fprintf(stderr, "SIGSEGV of unknown origin in singlestep mmap, we are doomed\n");
                        abort();
                    }
                }
                mmap_pointer_resume_access((void *)addr);            
            }
            else {
                fprintf(stderr, "SIGSEGV of unknown origin, not pointer tainting and not in protected address, we are doomed\n");
                abort();
            }
        }
        ptrace(tracee_continue, ppid, NULL, NULL);
    }
    cs_free(insn, 1);
    cs_close(&handle);
    return 1;
}

static size_t min_taint_size = 0, max_taint_size = ULONG_MAX;
static long unsigned nb_tainted = 0, nb_tainted_candidates = 0, first_tainted = 0, max_nb_tainted = ULONG_MAX;

extern void
__attribute__((constructor)) dw_init()
{
    char *arg = getenv("DW_MIN_SIZE");
    if(arg != NULL) min_taint_size = atol(arg);
    arg = getenv("DW_MAX_SIZE");
    if(arg != NULL) max_taint_size = atol(arg);
    arg = getenv("DW_MAX_NB_TAINTED");
    if(arg != NULL) max_nb_tainted = atol(arg);
    arg = getenv("DW_FIRST_TAINTED");
    if(arg != NULL) first_tainted = atol(arg);
    arg = getenv("DW_POINTER_METHOD");
    if(arg != NULL) pointer_method = atol(arg);
    arg = getenv("DW_TRACE_SYSCALL");
    if(arg != NULL && atol(arg) == 1) tracee_continue = PTRACE_SYSCALL;
    arg = getenv("DW_ADDRESS_METHOD");
    if(arg != NULL) address_method = atol(arg);
     
    fprintf(stderr, "INFO Min taint size %lu, max taint size %lu, max nb tainted %lu, first tainted %lu, pointer method %lu\n", min_taint_size, max_taint_size, max_nb_tainted, first_tainted, pointer_method);
    
    if ((malloc_metadata_size < MALLOC_METADATA_MIN_SIZE) || (malloc_metadata_size > MALLOC_METADATA_MAX_SIZE)) {
        //printf("Invalid malloc metadata table size");
        exit(-1);
    }
    
    //init metadata

    malloc_metadata = malloc(sizeof(object_id) * malloc_metadata_size);
    void *malloc_addr = (void *)malloc_metadata; // CHECK dropping volatile!?!
    mmap_pointer_module_init();
    
    // Pass the addr of the malloc metadata to the "child"
    ppid = getpid();
    ptid = gettid();
    fprintf(stderr, "INFO Process id of main thread %d, thread id %d\n", ppid, ptid);
    
    const int STACK_SIZE = 65536;
    char* stack = malloc(STACK_SIZE);
    if(pointer_method & 1 || tracee_continue == PTRACE_SYSCALL) {
        cpid = clone(child_program, stack + STACK_SIZE, CLONE_VM, malloc_addr);
        fprintf(stderr, "INFO Clone child created %d\n", cpid);
    } else fprintf(stderr, "INFO No child, comparison run, pointers not protected\n");

    child_stack_start = (void *)stack;
    child_stack_end = (void *)(stack + STACK_SIZE);

    // Put all the entries in the free list to start.
    // status gives the next in list or -1 at the end.
    // Currently, the freelist is managed like a stack which is simpler more cache hot
    // However, we may increase detection by removing from head and adding to tail.
    // Indeed, malloc often reuses the recently freed object
    // Now the recycled object will get the same taint and pointers to the old object will still seem valid.
    
    for(int i=0;i<malloc_metadata_size;i++){
        malloc_metadata[i].status = i + 1;
    }
    malloc_metadata[malloc_metadata_size - 1].status = -1;
    head = 0;

    sleep(2); /* we should wait for child to have attached */
    fprintf(stderr,"INFO Init completed\n");
    fprintf(stderr, "INFO Setting hooks active from %d\n", gettid());
    malloc_hook_active = 1;
}

static void *
dw_malloc_hook(size_t alignment, size_t size)
{
    void *result, *final_result;
    malloc_hook_active = 0;
    
    /* Call recursively */
    if(alignment <= 1) final_result = result = __libc_malloc(size);// extern void *__libc_realloc(void *ptr, size_t size);

    else final_result = result = __libc_memalign(alignment, size);
   
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

        final_result = (void *)SETTAINT(result, head + 1);    
        head = next_head;
    }
    fprintf(stderr,"INFO Malloc_hook %p (%p), size %lu\n", result, final_result, size);

    malloc_hook_active = 1;
    return final_result;
}

static void
dw_free_hook(void *ptr)
{
    void *final_ptr;
    
    final_ptr = ptr;
    long unsigned taint = (long long unsigned)GETTAINT(ptr);
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
        final_ptr = (void *)UNTAINT(ptr);
    }
    
    /* Call recursively */
    fprintf(stderr,"INFO Free_hook %p (%p)\n", final_ptr, ptr);
    __libc_free(final_ptr);
}

static int
tainted_check_size(void *ptr)
{
    long unsigned taint = (long long unsigned)GETTAINT(ptr);
    long index = taint - 1;

    if(index < 0 || index > malloc_metadata_size - 1) {
        fprintf(stderr, "Invalid taint value %lu\n", taint);
    }
    else if (malloc_metadata[index].status == -2) {
            if(ptr != malloc_metadata[index].base_addr) fprintf(stderr, "Error, not using base address for ptr %p in get size\n", ptr);
            return malloc_metadata[index].size;
    }
    return -1;
}

static int 
check_candidate(size_t size) {
    if(malloc_hook_active && size >= min_taint_size && size <= max_taint_size) {
        nb_tainted_candidates++;
        if(nb_tainted_candidates > first_tainted && nb_tainted < max_nb_tainted) {
            if((pointer_method & 4 && mmap_oid_last < mmap_metadata_size) || (pointer_method == 3 && head != -1)) {
                nb_tainted++;
                return 1;
            }
        }
    }
    return 0;
}

static int 
check_size(void *ptr)
{
    if(is_child()) return simple_check_size(ptr);
    if(GETTAINT(ptr)) return tainted_check_size(ptr);
    if(pointer_method & 4) return mmap_check_size(ptr);
    return -1;
}

void*
malloc(size_t size)
{
    if(is_child()) return simple_malloc(size);

    if(check_candidate(size)) {
        if(pointer_method & 4) return mmap_pointer_malloc_hook(size);
        else if(pointer_method == 3) return dw_malloc_hook(1, size);
    }
    void *ret = __libc_malloc(size);
    fprintf(stderr,"INFO Malloc %p, size %lu, nb_candidates %lu\n", ret, size, nb_tainted_candidates);
    return ret;
}

// Complete simple_malloc with size, revise the malloc/free/memalign hooks, add check_size

void*
realloc(void *ptr, size_t size)
{
    fprintf(stderr,"INFO Realloc %p, size %lu, replaced by free and malloc\n", ptr, size);
    void* ret = malloc(size);
    int old_size = check_size(ptr);

    // The object was not protected, its size is unknown
    if(old_size < 0) {
        ptr = __libc_realloc(ptr, size);
        old_size = size;
    }
    
    // Copy from the old object to the new
    memcpy(ret, ptr, old_size < size ? old_size : size);
    free(ptr);
    return ret;
}

void
free(void *ptr)
{
    if(is_child()) simple_free(ptr);
    else if(pointer_method & 4) mmap_pointer_free_hook(ptr);
    else if(GETTAINT(ptr) != 0) dw_free_hook(ptr);
    else {
        fprintf(stderr,"INFO Free %p\n", ptr);
        __libc_free(ptr);
    }
}

void*
memalign(size_t alignment, size_t size)
{
    if(is_child()) return simple_memalign(alignment, size);

    if(check_candidate(size)) {
        if(pointer_method & 4) return mmap_pointer_memalign_hook(alignment, size);
        else if(pointer_method == 3) return dw_malloc_hook(alignment, size);
    }
    void *ret = __libc_memalign(alignment, size);
    fprintf(stderr,"INFO Memalign %p, size %lu, nb_candidates %lu\n", ret, size, nb_tainted_candidates);
    return ret;
}

void*
calloc(size_t nmemb, size_t size)
{
    void *ret = malloc(nmemb * size);
    bzero(ret, nmemb * size);
    return ret;
}
