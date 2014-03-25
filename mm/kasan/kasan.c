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

struct static_key kasan_initialized = STATIC_KEY_INIT_FALSE;

static DEFINE_PER_CPU(int, kasan_disabled);

unsigned long kasan_shadow_start;
unsigned long kasan_shadow_end;

static inline bool addr_is_in_mem(unsigned long addr)
{
	return addr >= PAGE_OFFSET && addr < (unsigned long)high_memory;
}

static inline bool addr_is_in_shadow(unsigned long shadow_addr)
{
	return (shadow_addr >= kasan_shadow_start) &&
		(shadow_addr < kasan_shadow_end);
}

void kasan_enable_local(void)
{
	if (static_key_false(&kasan_initialized)) {
		this_cpu_dec(kasan_disabled);
		preempt_enable();
	}
}

void kasan_disable_local(void)
{
	if (static_key_false(&kasan_initialized)) {
		preempt_disable();
		this_cpu_inc(kasan_disabled);
	}
}

static inline bool kasan_enabled(void)
{
	return static_key_false(&kasan_initialized)
		&& !this_cpu_read(kasan_disabled);
}

/*
 * Poisons the shadow memory for 'size' bytes starting from 'addr'.
 * Memory addresses should be aligned to KASAN_SHADOW_SCALE_SIZE.
 */
static void poison_shadow(const void *address, size_t size, u8 value)
{
	unsigned long shadow_beg, shadow_end;
	unsigned long addr = (unsigned long)address;

	shadow_beg = kasan_mem_to_shadow(addr);
	shadow_end = kasan_mem_to_shadow(addr + size);

	memset((void *)shadow_beg, value, shadow_end - shadow_beg);
}

static void unpoison_shadow(const void *address, size_t size)
{
	poison_shadow(address, size, 0);

	if (size & KASAN_SHADOW_MASK) {
		u8 *shadow = (u8 *)kasan_mem_to_shadow((unsigned long)address
						+ size);
		*shadow = size & KASAN_SHADOW_MASK;
	}
}

static bool address_is_poisoned(unsigned long addr)
{
	s8 shadow_value = *(s8 *)kasan_mem_to_shadow(addr);

	if (shadow_value != 0) {
		s8 last_accessed_byte = addr & KASAN_SHADOW_MASK;
		return last_accessed_byte > shadow_value;
	}
	return false;
}

static bool memory_is_zero(const u8 *beg, size_t size)
{
	const u8 *end = beg + size;
	unsigned long beg_addr = (unsigned long)beg;
	unsigned long end_addr = (unsigned long)end;
	unsigned long *aligned_beg =
		(unsigned long *)round_up(beg_addr, sizeof(unsigned long));
	unsigned long *aligned_end =
		(unsigned long *)round_down(end_addr, sizeof(unsigned long));
	unsigned long all = 0;
	const u8 *mem;
	for (mem = beg; mem < (u8 *)aligned_beg && mem < end; mem++)
		all |= *mem;
	for (; aligned_beg < aligned_end; aligned_beg++)
		all |= *aligned_beg;
	if ((u8 *)aligned_end >= beg)
		for (mem = (u8 *)aligned_end; mem < end; mem++)
			all |= *mem;
	return all == 0;
}

/*
 * Returns address of the first poisoned byte if the memory region
 * lies in the physical memory and poisoned, returns 0 otherwise.
 */
static unsigned long memory_is_poisoned(unsigned long addr, size_t size)
{
	unsigned long beg, end;
	unsigned long aligned_beg, aligned_end;
	unsigned long shadow_beg, shadow_end;

	if (size == 0)
		return 0;

	beg = addr;
	end = beg + size;
	if (!addr_is_in_mem(beg) || !addr_is_in_mem(end))
		return 0;

	aligned_beg = round_up(beg, KASAN_SHADOW_SCALE_SIZE);
	aligned_end = round_down(end, KASAN_SHADOW_SCALE_SIZE);
	shadow_beg = kasan_mem_to_shadow(aligned_beg);
	shadow_end = kasan_mem_to_shadow(aligned_end);
	if (!address_is_poisoned(beg) &&
	    !address_is_poisoned(end - 1) &&
	    (shadow_end <= shadow_beg ||
		    memory_is_zero((const u8 *)shadow_beg, shadow_end - shadow_beg)))
		return 0;
	for (; beg < end; beg++)
		if (address_is_poisoned(beg))
			return beg;

	WARN_ON(1); /* Unreachable. */
	return 0;
}

static void check_memory_region(unsigned long addr, size_t size, bool write)
{
	unsigned long access_addr;
	struct access_info info;

	if (!kasan_enabled())
		return;

	access_addr = memory_is_poisoned(addr, size);
	if (access_addr == 0)
		return;

	info.access_addr = access_addr;
	info.access_size = size;
	info.shadow_addr = (u8 *)kasan_mem_to_shadow(access_addr);
	info.is_write = write;
	info.thread_id = current->pid;
	info.strip_addr = _RET_IP_;
	kasan_report_error(&info);
}

void __init kasan_alloc_shadow(void)
{
	unsigned long kernel_vm_size = (unsigned long)high_memory - PAGE_OFFSET;
	unsigned long kasan_shadow_size;
	phys_addr_t found_free_range;

	kasan_shadow_size = kernel_vm_size >> KASAN_SHADOW_SCALE_SHIFT;

	found_free_range = memblock_alloc(kasan_shadow_size, PAGE_SIZE);
	if (!found_free_range) {
		pr_err("Unable to reserve shadow region\n");
		return;
	}

	kasan_shadow_start = (unsigned long)phys_to_virt(found_free_range);
	kasan_shadow_end = kasan_shadow_start + kasan_shadow_size;

	pr_info("Shadow virt start: 0x%lx\n", kasan_shadow_start);
	pr_info("Shadow virt end: 0x%lx\n", kasan_shadow_end);
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
		static_key_slow_inc(&kasan_initialized);
	}
}

void kasan_alloc_slab_pages(struct page *page, int order)
{
	if (!static_key_false(&kasan_initialized))
		return;

	poison_shadow(page_address(page), PAGE_SIZE << order, KASAN_SLAB_REDZONE);
}

void kasan_free_slab_pages(struct page *page, int order)
{
	if (!static_key_false(&kasan_initialized))
		return;

	poison_shadow(page_address(page), PAGE_SIZE << order, KASAN_SLAB_FREE);
}

void kasan_slab_alloc(struct kmem_cache *cache, void *object)
{
	if (!static_key_false(&kasan_initialized))
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

	if (!static_key_false(&kasan_initialized))
		return;

	poison_shadow(object, rounded_up_size, KASAN_KMALLOC_FREE);
}

void kasan_kmalloc(struct kmem_cache *cache, const void *object, size_t size)
{
	unsigned long rounded_up_object_size = cache->size;

	if (!static_key_false(&kasan_initialized))
		return;

	if (object == NULL)
		return;

	poison_shadow(object, rounded_up_object_size,
		KASAN_KMALLOC_REDZONE);
	unpoison_shadow(object, size);
}
EXPORT_SYMBOL(kasan_kmalloc);

void kasan_kmalloc_large(const void *ptr, size_t size)
{
	struct page *page;
	unsigned long redzone_start;
	unsigned long redzone_end;

	if (!static_key_false(&kasan_initialized))
		return;

	if (unlikely(ptr == NULL))
		return;

	page = virt_to_head_page(ptr);
	redzone_start = round_up((unsigned long)(ptr + size),
				KASAN_SHADOW_SCALE_SIZE);
	redzone_end = (unsigned long)ptr + (PAGE_SIZE << compound_order(page));

	BUG_ON(redzone_end < redzone_start);

	unpoison_shadow(ptr, size);
	if (redzone_end > redzone_start)
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

	if (!static_key_false(&kasan_initialized))
		return;

	page = virt_to_page(ptr);
	poison_shadow(ptr, PAGE_SIZE << compound_order(page), KASAN_FREE_PAGE);
}

void kasan_alloc_pages(struct page *page, unsigned int order)
{
	if (!static_key_false(&kasan_initialized))
		return;

	if (page && !PageHighMem(page))
		unpoison_shadow(page_address(page), PAGE_SIZE << order);
}

void kasan_free_pages(struct page *page, unsigned int order)
{
	if (!static_key_false(&kasan_initialized))
		return;

	if (!PageHighMem(page))
		poison_shadow(page_address(page), PAGE_SIZE << order, KASAN_FREE_PAGE);
}

void *kasan_memcpy(void *dst, const void *src, size_t len)
{
	check_memory_region((unsigned long)src, len, false);
	check_memory_region((unsigned long)dst, len, true);

	return memcpy(dst, src, len);
}
EXPORT_SYMBOL(kasan_memcpy);

void *kasan_memset(void *ptr, int val, size_t len)
{
	check_memory_region((unsigned long)ptr, len, true);

	return memset(ptr, val, len);
}
EXPORT_SYMBOL(kasan_memset);

void *kasan_memmove(void *dst, const void *src, size_t len)
{
	check_memory_region((unsigned long)src, len, false);
	check_memory_region((unsigned long)dst, len, true);

	return memmove(dst, src, len);
}
EXPORT_SYMBOL(kasan_memmove);

void __kasan_read1(unsigned long addr)
{
	check_memory_region(addr, 1, false);
}
EXPORT_SYMBOL(__kasan_read1);

void __asan_load1(unsigned long addr)  __attribute__((alias("__kasan_read1")));

void __kasan_read2(unsigned long addr)
{
	check_memory_region(addr, 2, false);
}
EXPORT_SYMBOL(__kasan_read2);
void __asan_load2(unsigned long addr)  __attribute__((alias("__kasan_read2")));

void __kasan_read4(unsigned long addr)
{
	check_memory_region(addr, 4, false);
}
EXPORT_SYMBOL(__kasan_read4);

void __asan_load4(unsigned long addr)  __attribute__((alias("__kasan_read4")));

void __kasan_read8(unsigned long addr)
{
	check_memory_region(addr, 8, false);
}
EXPORT_SYMBOL(__kasan_read8);
void __asan_load8(unsigned long addr)  __attribute__((alias("__kasan_read8")));

void __kasan_read16(unsigned long addr)
{
	check_memory_region(addr, 16, false);
}
EXPORT_SYMBOL(__kasan_read16);
void __asan_load16(unsigned long addr)  __attribute__((alias("__kasan_read16")));

void __kasan_write1(unsigned long addr)
{
	check_memory_region(addr, 1, true);
}
EXPORT_SYMBOL(__kasan_write1);
void __asan_store1(unsigned long addr)  __attribute__((alias("__kasan_write1")));

void __kasan_write2(unsigned long addr)
{
	check_memory_region(addr, 2, true);
}
EXPORT_SYMBOL(__kasan_write2);
void __asan_store2(unsigned long addr)  __attribute__((alias("__kasan_write2")));

void __kasan_write4(unsigned long addr)
{
	check_memory_region(addr, 4, true);
}
EXPORT_SYMBOL(__kasan_write4);
void __asan_store4(unsigned long addr)  __attribute__((alias("__kasan_write4")));

void __kasan_write8(unsigned long addr)
{
	check_memory_region(addr, 8, true);
}
EXPORT_SYMBOL(__kasan_write8);
void __asan_store8(unsigned long addr)  __attribute__((alias("__kasan_write8")));

void __kasan_write16(unsigned long addr)
{
	check_memory_region(addr, 16, true);
}
EXPORT_SYMBOL(__kasan_write16);

void __asan_store16(unsigned long addr)  __attribute__((alias("__kasan_write16")));

void __asan_init_v3(void) {}
void __asan_handle_no_return(void) {}
//unsigned long __asan_get_shadow_ptr(void) {return 0;}
