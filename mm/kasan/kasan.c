/*
 *
 * Copyright (c) 2014 Samsung Electronics Co., Ltd.
 * Author: Andrey Ryabinin <a.ryabinin@samsung.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/export.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/memblock.h>
#include <linux/mm.h>
#include <linux/printk.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/stacktrace.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/kasan.h>
#include <linux/memcontrol.h>

#include "kasan.h"
#include "../slab.h"

static bool __read_mostly kasan_initialized;

unsigned long kasan_shadow_start;
unsigned long kasan_shadow_end;

/* equals to (kasan_shadow_start - PAGE_OFFSET/KASAN_SHADOW_SCALE_SIZE) */
unsigned long __read_mostly kasan_shadow_offset; /* it's not a very good name for this variable */


static inline bool addr_is_in_mem(unsigned long addr)
{
	return likely(addr >= PAGE_OFFSET && addr < (unsigned long)high_memory);
}

void kasan_enable_local(void)
{
	if (likely(kasan_initialized))
		current->kasan_depth--;
}

void kasan_disable_local(void)
{
	if (likely(kasan_initialized))
		current->kasan_depth++;
}

static inline bool kasan_enabled(void)
{
	return likely(kasan_initialized
		&& !current->kasan_depth);
}

/*
 * Poisons the shadow memory for 'size' bytes starting from 'addr'.
 * Memory addresses should be aligned to KASAN_SHADOW_SCALE_SIZE.
 */
static void poison_shadow(const void *address, size_t size, u8 value)
{
	unsigned long shadow_start, shadow_end;
	unsigned long addr = (unsigned long)address;

	shadow_start = kasan_mem_to_shadow(addr);
	shadow_end = kasan_mem_to_shadow(addr + size);

	memset((void *)shadow_start, value, shadow_end - shadow_start);
}

void unpoison_shadow(const void *address, size_t size)
{
	poison_shadow(address, size, 0);

	if (size & KASAN_SHADOW_MASK) {
		u8 *shadow = (u8 *)kasan_mem_to_shadow((unsigned long)address
						+ size);
		*shadow = size & KASAN_SHADOW_MASK;
	}
}

static __always_inline bool address_is_poisoned(unsigned long addr)
{
	s8 shadow_value = *(s8 *)kasan_mem_to_shadow(addr);

	if (shadow_value != 0) {
		s8 last_byte = addr & KASAN_SHADOW_MASK;
		return last_byte >= shadow_value;
	}
	return false;
}

static __always_inline unsigned long memory_is_poisoned(unsigned long addr,
							size_t size)
{
	unsigned long end = addr + size;
	for (; addr < end; addr++)
		if (unlikely(address_is_poisoned(addr)))
			return addr;
	return 0;
}

static __always_inline void check_memory_region(unsigned long addr,
						size_t size, bool write)
{
	unsigned long access_addr;
	struct access_info info;

	if (!kasan_enabled())
		return;

	if (unlikely(addr < TASK_SIZE)) {
		info.access_addr = addr;
		info.access_size = size;
		info.is_write = write;
		info.ip = _RET_IP_;
		kasan_report_user_access(&info);
		return;
	}

	if (!addr_is_in_mem(addr))
		return;

	access_addr = memory_is_poisoned(addr, size);
	if (likely(access_addr == 0))
		return;

	info.access_addr = access_addr;
	info.access_size = size;
	info.is_write = write;
	info.ip = _RET_IP_;
	kasan_report_error(&info);
}

void __init kasan_alloc_shadow(void)
{
	unsigned long lowmem_size = (unsigned long)high_memory - PAGE_OFFSET;
	unsigned long shadow_size;
	phys_addr_t shadow_phys_start;

	shadow_size = lowmem_size >> KASAN_SHADOW_SCALE_SHIFT;

	shadow_phys_start = memblock_alloc(shadow_size, PAGE_SIZE);
	if (!shadow_phys_start) {
		pr_err("Unable to reserve shadow memory\n");
		return;
	}

	kasan_shadow_start = (unsigned long)phys_to_virt(shadow_phys_start);
	kasan_shadow_end = kasan_shadow_start + shadow_size;

	pr_info("reserved shadow memory: [0x%lx - 0x%lx]\n",
		kasan_shadow_start, kasan_shadow_end);
	kasan_shadow_offset = kasan_shadow_start -
		(PAGE_OFFSET >> KASAN_SHADOW_SCALE_SHIFT);
}

void __init kasan_init_shadow(void)
{
	if (kasan_shadow_start) {
		unpoison_shadow((void *)PAGE_OFFSET,
				(size_t)(kasan_shadow_start - PAGE_OFFSET));
		poison_shadow((void *)kasan_shadow_start,
			kasan_shadow_end - kasan_shadow_start,
			KASAN_SHADOW_GAP);
		unpoison_shadow((void *)kasan_shadow_end,
				(size_t)(high_memory - kasan_shadow_end));
		kasan_initialized = true;
		pr_info("shadow memory initialized\n");
	}
}

void kasan_alloc_slab_pages(struct page *page, int order)
{
	if (unlikely(!kasan_initialized))
		return;

	poison_shadow(page_address(page), PAGE_SIZE << order, KASAN_SLAB_REDZONE);
}

void kasan_free_slab_pages(struct page *page, int order)
{
	if (unlikely(!kasan_initialized))
		return;

	poison_shadow(page_address(page), PAGE_SIZE << order, KASAN_SLAB_FREE);
}

void kasan_slab_alloc(struct kmem_cache *cache, void *object)
{
	if (unlikely(!kasan_initialized))
		return;

	if (unlikely(object == NULL))
		return;

	poison_shadow(object, cache->size, KASAN_KMALLOC_REDZONE);
	unpoison_shadow(object, cache->alloc_size);
}

void kasan_slab_free(struct kmem_cache *cache, void *object)
{
	unsigned long size = cache->size;
	unsigned long rounded_up_size = round_up(size, KASAN_SHADOW_SCALE_SIZE);

	if (unlikely(!kasan_initialized))
		return;

	poison_shadow(object, rounded_up_size, KASAN_KMALLOC_FREE);
}

void kasan_kmalloc(struct kmem_cache *cache, const void *object, size_t size)
{
	unsigned long redzone_start;
	unsigned long redzone_end;

	if (unlikely(!kasan_initialized))
		return;

	if (unlikely(object == NULL))
		return;

	redzone_start = round_up((unsigned long)(object + size),
				KASAN_SHADOW_SCALE_SIZE);
	redzone_end = (unsigned long)object + cache->size;

	unpoison_shadow(object, size);
	poison_shadow((void *)redzone_start, redzone_end - redzone_start,
		KASAN_KMALLOC_REDZONE);

}
EXPORT_SYMBOL(kasan_kmalloc);

void kasan_kmalloc_large(const void *ptr, size_t size)
{
	struct page *page;
	unsigned long redzone_start;
	unsigned long redzone_end;

	if (unlikely(!kasan_initialized))
		return;

	if (unlikely(ptr == NULL))
		return;

	page = virt_to_page(ptr);
	redzone_start = round_up((unsigned long)(ptr + size),
				KASAN_SHADOW_SCALE_SIZE);
	redzone_end = (unsigned long)ptr + (PAGE_SIZE << compound_order(page));

	unpoison_shadow(ptr, size);
	poison_shadow((void *)redzone_start, redzone_end - redzone_start,
		KASAN_PAGE_REDZONE);
}
EXPORT_SYMBOL(kasan_kmalloc_large);

void kasan_krealloc(const void *object, size_t size)
{
	struct page *page;

	if (unlikely(object == ZERO_SIZE_PTR))
		return;

	page = virt_to_head_page(object);

	if (unlikely(!PageSlab(page)))
		kasan_kmalloc_large(object, size);
	else
		kasan_kmalloc(page->slab_cache, object, size);
}

void kasan_kfree_large(const void *ptr)
{
	struct page *page;

	if (unlikely(!kasan_initialized))
		return;

	page = virt_to_page(ptr);
	poison_shadow(ptr, PAGE_SIZE << compound_order(page), KASAN_FREE_PAGE);
}

void kasan_alloc_pages(struct page *page, unsigned int order)
{
	if (unlikely(!kasan_initialized))
		return;

	if (likely(page && !PageHighMem(page)))
		unpoison_shadow(page_address(page), PAGE_SIZE << order);
}

void kasan_free_pages(struct page *page, unsigned int order)
{
	if (unlikely(!kasan_initialized))
		return;

	if (likely(!PageHighMem(page)))
		poison_shadow(page_address(page), PAGE_SIZE << order, KASAN_FREE_PAGE);
}

void *kasan_memcpy(void *dst, const void *src, size_t len)
{
	if (unlikely(len == 0))
		return dst;

	check_memory_region((unsigned long)src, len, false);
	check_memory_region((unsigned long)dst, len, true);

	return memcpy(dst, src, len);
}
EXPORT_SYMBOL(kasan_memcpy);

void *kasan_memset(void *ptr, int val, size_t len)
{
	if (unlikely(len == 0))
		return ptr;

	check_memory_region((unsigned long)ptr, len, true);

	return memset(ptr, val, len);
}
EXPORT_SYMBOL(kasan_memset);

void *kasan_memmove(void *dst, const void *src, size_t len)
{
	if (unlikely(len == 0))
		return dst;

	check_memory_region((unsigned long)src, len, false);
	check_memory_region((unsigned long)dst, len, true);

	return memmove(dst, src, len);
}
EXPORT_SYMBOL(kasan_memmove);

void __asan_load1(unsigned long addr)
{
	check_memory_region(addr, 1, false);
}
EXPORT_SYMBOL(__asan_load1);

void __asan_load2(unsigned long addr)
{
	check_memory_region(addr, 2, false);
}
EXPORT_SYMBOL(__asan_load2);

void __asan_load4(unsigned long addr)
{
	check_memory_region(addr, 4, false);
}
EXPORT_SYMBOL(__asan_load4);

void __asan_load8(unsigned long addr)
{
	check_memory_region(addr, 8, false);
}
EXPORT_SYMBOL(__asan_load8);

void __asan_load16(unsigned long addr)
{
	check_memory_region(addr, 16, false);
}
EXPORT_SYMBOL(__asan_load16);

void __asan_loadN(unsigned long addr, size_t size)
{
	if (unlikely(size == 0))
		return;

	check_memory_region(addr, size, false);
}
EXPORT_SYMBOL(__asan_loadN);

void __asan_store1(unsigned long addr)
{
	check_memory_region(addr, 1, true);
}
EXPORT_SYMBOL(__asan_store1);

void __asan_store2(unsigned long addr)
{
	check_memory_region(addr, 2, true);
}
EXPORT_SYMBOL(__asan_store2);

void __asan_store4(unsigned long addr)
{
	check_memory_region(addr, 4, true);
}
EXPORT_SYMBOL(__asan_store4);

void __asan_store8(unsigned long addr)
{
	check_memory_region(addr, 8, true);
}
EXPORT_SYMBOL(__asan_store8);

void __asan_store16(unsigned long addr)
{
	check_memory_region(addr, 16, true);
}
EXPORT_SYMBOL(__asan_store16);

void __asan_storeN(unsigned long addr, size_t size)
{
	if (unlikely(size == 0))
		return;

	check_memory_region(addr, size, true);
}
EXPORT_SYMBOL(__asan_storeN);

/* to shut up compiler complains */
void __asan_init_v3(void) {}
EXPORT_SYMBOL(__asan_init_v3);

void __asan_handle_no_return(void) {}
EXPORT_SYMBOL(__asan_handle_no_return);
