#ifndef _LINUX_KASAN_H
#define _LINUX_KASAN_H

#include <linux/types.h>

struct kmem_cache;
struct page;

#ifdef CONFIG_KASAN
#include <asm/kasan.h>
#include <linux/sched.h>

#define KASAN_SHADOW_SCALE_SHIFT 3
#define KASAN_SHADOW_OFFSET _AC(CONFIG_KASAN_SHADOW_OFFSET, UL)

static inline unsigned long kasan_mem_to_shadow(unsigned long addr)
{
	return (addr >> KASAN_SHADOW_SCALE_SHIFT) + KASAN_SHADOW_OFFSET;
}

static inline void kasan_enable_local(void)
{
	current->kasan_depth++;
}

static inline void kasan_disable_local(void)
{
	current->kasan_depth--;
}

void kasan_unpoison_shadow(const void *address, size_t size);

void kasan_alloc_pages(struct page *page, unsigned int order);
void kasan_free_pages(struct page *page, unsigned int order);

#else /* CONFIG_KASAN */

static inline void kasan_unpoison_shadow(const void *address, size_t size) {}

static inline void kasan_enable_local(void) {}
static inline void kasan_disable_local(void) {}

static inline void kasan_alloc_pages(struct page *page, unsigned int order) {}
static inline void kasan_free_pages(struct page *page, unsigned int order) {}

#endif /* CONFIG_KASAN */

#endif /* LINUX_KASAN_H */
