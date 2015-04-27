#include <linux/kasan.h>
#include <linux/kernel.h>
#include <linux/init.h>

#include <asm/page.h>
#include <asm/pgalloc.h>

#ifndef PAGE_KERNEL_RO
#define PAGE_KERNEL_RO PAGE_KERNEL
#endif

static int __init zero_pte_populate(pmd_t *pmd, unsigned long addr,
				unsigned long end)
{
	pte_t *pte = pte_offset_kernel(pmd, addr);

	while (addr + PAGE_SIZE <= end) {
		set_pte(pte, pfn_pte(virt_to_pfn(kasan_zero_page),
					PAGE_KERNEL_RO));
		addr += PAGE_SIZE;
		pte = pte_offset_kernel(pmd, addr);
	}
	return 0;
}

static int __init zero_pmd_populate(pud_t *pud, unsigned long addr,
				unsigned long end)
{
	int ret = 0;
	pmd_t *pmd = pmd_offset(pud, addr);

	while (IS_ALIGNED(addr, PMD_SIZE) && addr + PMD_SIZE <= end) {
		pmd_populate_kernel(&init_mm, pmd, kasan_zero_pte);
		addr = pmd_addr_end(addr, end);
		if (addr >= end)
			break;
		pmd++;
	}

	if (addr < end) {
		if (pmd_none(*pmd)) {
			void *p = vmemmap_alloc_block(PAGE_SIZE, NUMA_NO_NODE);
			if (!p)
				return -ENOMEM;
			pmd_populate_kernel(&init_mm, pmd, p);
		}
		ret = zero_pte_populate(pmd, addr, end);
	}
	return ret;
}

static int __init zero_pud_populate(pgd_t *pgd, unsigned long addr,
				unsigned long end)
{
	int ret = 0;
	pud_t *pud = pud_offset(pgd, addr);

	while (IS_ALIGNED(addr, PUD_SIZE) && addr + PUD_SIZE <= end) {
		pud_populate(&init_mm, pud, kasan_zero_pmd);
		zero_pmd_populate(pud, addr, pud_addr_end(addr, end));
		addr = pud_addr_end(addr, end);
		if (addr >= end)
			break;
		pud++;
	}

	if (addr < end) {
		if (pud_none(*pud)) {
			void *p = vmemmap_alloc_block(PAGE_SIZE, NUMA_NO_NODE);
			if (!p)
				return -ENOMEM;
			pud_populate(&init_mm, pud, p);
		}
		ret = zero_pmd_populate(pud, addr, end);
	}
	return ret;
}

static int __init zero_pgd_populate(unsigned long addr, unsigned long end)
{
	int ret = 0;
	pgd_t *pgd = pgd_offset_k(addr);

	while (IS_ALIGNED(addr, PGDIR_SIZE) && (addr + PGDIR_SIZE) <= end) {
		pgd_populate(&init_mm, pgd, kasan_zero_pud);
		zero_pud_populate(pgd, addr, pgd_addr_end(addr, end));
		addr = pgd_addr_end(addr, end);
		if (addr >= end)
			break;
		pgd++;
	}

	if (addr < end) {
		if (pgd_none(*pgd)) {
			void *p = vmemmap_alloc_block(PAGE_SIZE, NUMA_NO_NODE);
			if (!p)
				return -ENOMEM;
			pgd_populate(&init_mm, pgd, p);
		}
		ret = zero_pud_populate(pgd, addr, end);
	}
	return ret;
}

void __init kasan_populate_zero_shadow(const void *start, const void *end)
{
	if (zero_pgd_populate((unsigned long)start, (unsigned long)end))
		panic("kasan: unable to map zero shadow!");
}
