#ifndef __MM_KASAN_KASAN_H
#define __MM_KASAN_KASAN_H

#include <linux/kasan.h>

#define KASAN_SHADOW_SCALE_SIZE (1UL << KASAN_SHADOW_SCALE_SHIFT)
#define KASAN_SHADOW_MASK       (KASAN_SHADOW_SCALE_SIZE - 1)

#define KASAN_FREE_PAGE         0xFF  /* page was freed */
#define KASAN_PAGE_REDZONE      0xFE  /* redzone for kmalloc_large allocations */
#define KASAN_SLAB_PADDING      0xFD  /* Slab page padding, does not belong to any slub object */
#define KASAN_KMALLOC_REDZONE   0xFC  /* redzone inside slub object */
#define KASAN_KMALLOC_FREE      0xFB  /* object was freed (kmem_cache_free/kfree) */
#define KASAN_SLAB_FREE         0xFA  /* free slab page */
#define KASAN_SHADOW_GAP        0xF9  /* address belongs to shadow memory */

struct access_info {
	unsigned long access_addr;
	unsigned long first_bad_addr;
	size_t access_size;
	bool is_write;
	unsigned long ip;
};

extern unsigned long kasan_shadow_start;
extern unsigned long kasan_shadow_end;
extern unsigned long kasan_shadow_offset;

void kasan_report_error(struct access_info *info);
void kasan_report_user_access(struct access_info *info);

static inline unsigned long kasan_shadow_to_mem(unsigned long shadow_addr)
{
	return (shadow_addr - KASAN_SHADOW_OFFSET) << KASAN_SHADOW_SCALE_SHIFT;
}

#endif
