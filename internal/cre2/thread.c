#include <limits.h>
#include <stdlib.h>
#include <pthread.h>

void *__copy_tls(unsigned char *mem);

enum {
	DT_EXITED = 0,
	DT_EXITING,
	DT_JOINABLE,
	DT_DETACHED,
};

struct pthread {
	/* Part 1 -- these fields may be external or
	 * internal (accessed via asm) ABI. Do not change. */
    struct pthread *self;
	struct pthread *prev, *next; /* non-ABI */
	uintptr_t sysinfo;
	uintptr_t canary;

	/* Part 2 -- implementation details, non-ABI. */
	int tid;
	int errno_val;
	volatile int detach_state;
	volatile int cancel;
	volatile unsigned char canceldisable, cancelasync;
	unsigned char tsd_used:1;
	unsigned char dlerror_flag:1;
	unsigned char *map_base;
	size_t map_size;
	void *stack;
	size_t stack_size;
	size_t guard_size;
	void *result;
	struct __ptcb *cancelbuf;
	void **tsd;
	struct {
		volatile void *volatile head;
		long off;
		volatile void *volatile pending;
	} robust_list;
	int h_errno_val;
	volatile int timer_id;
	locale_t locale;
	volatile int killlock[1];
	char *dlerror_buf;
	void *stdio_locks;
};

extern _Thread_local struct __pthread __wasilibc_pthread_self;

static inline uintptr_t __get_tp() {
  return (uintptr_t)&__wasilibc_pthread_self;
}

#define __pthread_self() ((pthread_t)__get_tp())
#define ROUND(x) (((x)+16-1)&-16)

void wasi_new_thread(void** out_new_tls_base, void** out_new_stack) {
  struct pthread *self, *new;
  size_t tls_size = __builtin_wasm_tls_size();
  size_t tls_align = __builtin_wasm_tls_align();
  void* tls_base = __builtin_wasm_tls_base();
  void* new_tls_base;
  size_t tls_offset;
  tls_size += tls_align;

  self = __pthread_self();

  size_t __pthread_tsd_size = sizeof(void *) * PTHREAD_KEYS_MAX;
  size_t size = ROUND(tls_size + 65536 + __pthread_tsd_size);

  unsigned char *map = 0, *stack = 0, *tsd = 0, *stack_limit;
  map = malloc(size);
  tsd = map + size - __pthread_tsd_size;
  stack = tsd - tls_size;
  stack_limit = map;
  new_tls_base = __copy_tls(tsd - tls_size);
  tls_offset = new_tls_base - tls_base;

  new = (void*)((uintptr_t)self + tls_offset);
  new->map_base = map;
  new->map_size = size;
  new->stack = stack;
  new->stack_size = stack - stack_limit;
  new->guard_size = 0;
  new->self = new;
  new->tsd = (void *)tsd;
  // new->locale = &libc.global_locale;
  new->detach_state = DT_DETACHED;
  new->robust_list.head = &new->robust_list.head;
  new->canary = self->canary;
  new->sysinfo = self->sysinfo;

  new->stack = (void *)((uintptr_t) stack & -16);
  new->stack_size = stack - stack_limit;

  *out_new_tls_base = new_tls_base;
  *out_new_stack = new->stack;
}
