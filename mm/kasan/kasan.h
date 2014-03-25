/*
 *
 * Copyright (c) 2014 Samsung Electronics Co., Ltd.
 * Author: Andrey Ryabinin <a.ryabinin@samsung.com>
 *
 * Some of code borrowed from https://github.com/xairy/linux by
 *        Andrey Konovalov <andreyknvl@google.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */
#ifndef __MM_KASAN_KASAN_H
#define __MM_KASAN_KASAN_H

#define KASAN_SHADOW_SCALE_SHIFT 3
#define KASAN_SHADOW_SCALE_SIZE (1UL << KASAN_SHADOW_SCALE_SHIFT)
#define KASAN_SHADOW_MASK       (KASAN_SHADOW_SCALE_SIZE - 1)

#define KASAN_FREE_PAGE         0xFF  /* page was freed */
#define KASAN_PAGE_REDZONE      0xFE  /* redzone for kmalloc_large allocations */
#define KASAN_SLAB_REDZONE      0xFD  /* Slab page redzone, does not belong to any slub object */
#define KASAN_KMALLOC_REDZONE   0xFC  /* redzone inside slub object */
#define KASAN_KMALLOC_FREE      0xFB  /* object was freed (kmem_cache_free/kfree) */
#define KASAN_SLAB_FREE         0xFA  /* free slab page */
#define KASAN_SHADOW_GAP        0xF9  /* address belongs to shadow memory */

struct access_info {
	unsigned long access_addr;
	size_t access_size;
	u8 *shadow_addr;
	bool is_write;
	pid_t thread_id;
	unsigned long strip_addr;
};

extern unsigned long kasan_shadow_start;
extern unsigned long kasan_shadow_end;

void kasan_report_error(struct access_info *info);

static inline unsigned long kasan_mem_to_shadow(unsigned long addr)
{
	return ((addr - PAGE_OFFSET) >> KASAN_SHADOW_SCALE_SHIFT)
		+ kasan_shadow_start;
}

static inline unsigned long kasan_shadow_to_mem(unsigned long shadow_addr)
{
	return ((shadow_addr - kasan_shadow_start)
		<< KASAN_SHADOW_SCALE_SHIFT) + PAGE_OFFSET;
}

#endif
