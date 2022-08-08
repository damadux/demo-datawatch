#ifndef libdw_h__
#define libdw_h__

typedef __uint64_t uint64_t;
/*
static void *dw_realloc_hook (void *, size_t, const void *);
static void *dw_malloc_hook (size_t, const void *);
static void dw_free_hook (void*, const void *);
static void *dw_memalign_hook(size_t, size_t, const void*);

static void *(*old_malloc_hook) (size_t, const void *);
static void *(*old_realloc_hook) (void *, size_t, const void *);
static void (*old_free_hook) (void*, const void *);
static void* (* old_memalign_hook)(size_t, size_t, const void*);

extern void* get_original_address(void*);
extern uint64_t memory_access(uint64_t, uint64_t);
extern uint64_t memory_access_dbg(uint64_t,uint64_t);
static void dw_init (void);
extern void final_check(void);
*/
//static void *malloc_hook (size_t, const void *);

//static void *(*old_malloc_hook) (size_t, const void *);

//extern uint64_t memory_access(uint64_t, uint64_t);
//extern uint64_t memory_access_dbg(uint64_t,uint64_t);
extern void dw_init (void);
//extern void final_check(void);

#endif
