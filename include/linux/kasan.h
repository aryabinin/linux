#ifndef _LINUX_KASAN_H
#define _LINUX_KASAN_H

#include <linux/types.h>

struct kmem_cache;
struct page;

#ifdef CONFIG_KASAN

void unpoison_shadow(const void *address, size_t size);

void kasan_enable_local(void);
void kasan_disable_local(void);

/* Reserves shadow memory. */
void kasan_alloc_shadow(void);
void kasan_init_shadow(void);

#else /* CONFIG_KASAN */

static inline void unpoison_shadow(const void *address, size_t size) {}

static inline void kasan_enable_local(void) {}
static inline void kasan_disable_local(void) {}

/* Reserves shadow memory. */
static inline void kasan_init_shadow(void) {}
static inline void kasan_alloc_shadow(void) {}

#endif /* CONFIG_KASAN */

#endif /* LINUX_KASAN_H */
