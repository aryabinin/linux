#ifndef _LINUX_KASAN_H
#define _LINUX_KASAN_H

#include <linux/types.h>

struct kmem_cache;
struct page;

#ifdef CONFIG_KASAN

void kasan_enable_local(void);
void kasan_disable_local(void);

/* Reserves shadow memory. */
void kasan_alloc_shadow(void);
void kasan_init_shadow(void);

void kasan_alloc_pages(struct page *page, unsigned int order);
void kasan_free_pages(struct page *page, unsigned int order);

void kasan_kmalloc_large(const void *ptr, size_t size);
void kasan_kfree_large(const void *ptr);
void kasan_kmalloc(struct kmem_cache *s, const void *object, size_t size);
void kasan_krealloc(const void *object, size_t new_size);

void kasan_slab_alloc(struct kmem_cache *s, void *object);
void kasan_slab_free(struct kmem_cache *s, void *object);

void kasan_alloc_slab_pages(struct page *page, int order);
void kasan_free_slab_pages(struct page *page, int order);

#else /* CONFIG_KASAN */

static inline void kasan_enable_local(void) {}
static inline void kasan_disable_local(void) {}

/* Reserves shadow memory. */
static inline void kasan_init_shadow(void) {}
static inline void kasan_poison(void) {}

static inline void kasan_alloc_pages(struct page *page, unsigned int order) {}
static inline void kasan_free_pages(struct page *page, unsigned int order) {}

static inline void kasan_kmalloc_large(void *ptr, size_t size) {}
static inline void kasan_kfree_large(const void *ptr) {}
static inline void kasan_kmalloc(struct kmem_cache *s, const void *object, size_t size) {}
static inline void kasan_krealloc(const void *object, size_t new_size) {}

static inline void kasan_slab_alloc(struct kmem_cache *s, void *object) {}
static inline void kasan_slab_free(struct kmem_cache *s, void *object) {}

static inline void kasan_alloc_slab_pages(struct page *page, int order) {}
static inline void kasan_free_slab_pages(struct page *page, int order) {}

#endif /* CONFIG_KASAN */

#endif /* LINUX_KASAN_H */
