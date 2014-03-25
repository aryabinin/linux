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

#define pr_fmt(fmt) "kasan test: " fmt

#include <linux/kernel.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/module.h>

/* Expected to produce a report. */
void kasan_do_bo(void)
{
	char *ptr;

	pr_err("TEST: out-of-bounds:\n");
	ptr = kmalloc(4096+30 , GFP_KERNEL);
	*(ptr + 4096+35) = 'x';
	kfree(ptr);
}

/* Expected to produce a report. */
void kasan_do_bo_kmalloc(void)
{
	char *ptr;

	pr_err("TEST: out-of-bounds in kmalloc redzone:\n");
	ptr = kmalloc(17, GFP_KERNEL);
	*(ptr + 18) = 'x';
	kfree(ptr);
}

/* Expected to produce a report. */
void kasan_do_bo_kmalloc_node(void)
{
	char *ptr;

	pr_err("TEST: out-of-bounds in kmalloc_node redzone:\n");
	ptr = kmalloc_node(17, GFP_KERNEL, 0);
	*(ptr + 18) = 'x';
	kfree(ptr);
}

/* Expected to produce a report. */
void kasan_do_bo_krealloc(void)
{
	char *ptr1, *ptr2;

	pr_err("TEST: out-of-bounds after krealloc:\n");
	ptr1 = kmalloc(17, GFP_KERNEL);
	ptr2 = krealloc(ptr1, 19, GFP_KERNEL);
	ptr2[20] = 'x';
	kfree(ptr2);
}

/* Expected to produce a report. */
void kasan_do_bo_krealloc_less(void)
{
	char *ptr1, *ptr2;

	pr_err("TEST: out-of-bounds after krealloc 2:\n");
	ptr1 = kmalloc(17, GFP_KERNEL);
	ptr2 = krealloc(ptr1, 15, GFP_KERNEL);
	ptr2[16] = 'x';
	kfree(ptr2);
}

/* Expected not to produce a report. */
void kasan_do_krealloc_more(void)
{
	char *ptr1, *ptr2;

	pr_err("TEST: access addressable memory after krealloc.\n");
	ptr1 = kmalloc(17, GFP_KERNEL);
	ptr2 = krealloc(ptr1, 19, GFP_KERNEL);
	ptr2[18] = 'x';
	kfree(ptr2);
}

/* Expected to produce a report. */
void kasan_do_bo_left(void)
{
	char *ptr;

	pr_err("TEST: out-of-bounds to the left:\n");
	ptr = kmalloc(17, GFP_KERNEL);
	*(ptr - 1) = 'x';
	kfree(ptr);
}

/* Expected to produce a report. */
void kasan_do_bo_16(void)
{
	struct {
		u64 words[2];
	} *ptr1, *ptr2;

	pr_err("TEST: out-of-bounds for 16-bytes access:\n");
	ptr1 = kmalloc(10, GFP_KERNEL);
	ptr2 = kmalloc(16, GFP_KERNEL);
	*ptr1 = *ptr2;
	kfree(ptr1);
	kfree(ptr2);
}

/* Expected to produce a report. */
void kasan_do_bo_4mb(void)
{
	char *ptr;

	pr_err("TEST: out-of-bounds in 4mb cache:\n");
	ptr = kmalloc((4 << 20), GFP_KERNEL);
	if (ptr)
		ptr[0] = ptr[(4 << 20) + 1];
}

/* Expected to produce a report. */
void kasan_do_bo_memset(void)
{
	char *ptr;

	pr_err("TEST: out-of-bounds in memset:\n");
	ptr = kmalloc(33, GFP_KERNEL);
	memset(ptr, 0, 40);
	kfree(ptr);
}

/* Expected to produce a report. */
void kasan_do_uaf(void)
{
	char *ptr;

	pr_err("TEST: use-after-free:\n");
	ptr = kmalloc(128, GFP_KERNEL);
	kfree(ptr);
	*(ptr + 126 - 64) = 'x';
}

/* Expected to produce a report. */
void kasan_do_uaf_memset(void)
{
	char *ptr;

	pr_err("TEST: use-after-free in memset:\n");
	ptr = kmalloc(33, GFP_KERNEL);
	kfree(ptr);
	memset(ptr, 0, 30);
}

/* Expected to produce a report. */
void kasan_do_uaf_quarantine(void)
{
	char *ptr1, *ptr2;

	pr_err("TEST: use-after-free in quarantine:\n");
	ptr1 = kmalloc(42, GFP_KERNEL);
	kfree(ptr1);
	ptr2 = kmalloc(42, GFP_KERNEL);
	ptr1[5] = 'x';
	kfree(ptr2);
}

void kasan_do_4mb_kmem_cache(void)
{
	char *p;
	struct kmem_cache *cache = kmem_cache_create("kasan_test_cache",
						128, 0,
						0, NULL);
	if (!cache) {
		pr_err("Cache allocation failed\n");
		return;
	}
	p = kmem_cache_alloc(cache, GFP_KERNEL);
	if (!p) {
		pr_err("Allocation failed\n");
		return;
	}

	*p = p[(128+2)];
	kmem_cache_free(cache, p);
	kmem_cache_destroy(cache);
}

/* Expected to produce a report and cause kernel panic. */
void kasan_do_user_memory_access(void)
{
	char *ptr1 = (char *)(1UL << 24);
	char *ptr2;

	pr_err("TEST: user-memory-access:\n");
	ptr2 = kmalloc(10, GFP_KERNEL);
	ptr2[3] = *ptr1;
	kfree(ptr2);
}

int __init kasan_tests_init(void)
{
	kasan_do_bo();
	kasan_do_bo_left();
	kasan_do_bo_kmalloc();
	kasan_do_bo_kmalloc_node();
	kasan_do_bo_krealloc();
	kasan_do_bo_krealloc_less();
	kasan_do_krealloc_more();
	kasan_do_bo_16();
	kasan_do_bo_4mb();
	kasan_do_bo_memset();
	kasan_do_uaf();
	kasan_do_uaf_memset();
	kasan_do_uaf_quarantine();
	kasan_do_4mb_kmem_cache();
	return 0;
}

module_init(kasan_tests_init);
