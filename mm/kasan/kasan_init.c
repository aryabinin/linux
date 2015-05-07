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
	unsigned long next;

	do {
		next = pmd_addr_end(addr, end);

		if (IS_ALIGNED(addr, PMD_SIZE) && end - addr >= PMD_SIZE) {
			pmd_populate_kernel(&init_mm, pmd, kasan_zero_pte);
			continue;
		}

		if (pmd_none(*pmd)) {
			void *p = vmemmap_alloc_block(PAGE_SIZE, NUMA_NO_NODE);
			if (!p)
				return -ENOMEM;
			pmd_populate_kernel(&init_mm, pmd, p);
		}
		zero_pte_populate(pmd, addr, pmd_addr_end(addr, end));
	} while (pmd++, addr = next, addr != end);

	return ret;
}

static int __init zero_pud_populate(pgd_t *pgd, unsigned long addr,
				unsigned long end)
{
	int ret = 0;
	pud_t *pud = pud_offset(pgd, addr);
	unsigned long next;

	do {
		next = pud_addr_end(addr, end);
		if (IS_ALIGNED(addr, PUD_SIZE) && end - addr >= PUD_SIZE) {
			pmd_t *pmd;

			pud_populate(&init_mm, pud, kasan_zero_pmd);
			pmd = pmd_offset(pud, addr);
			pmd_populate_kernel(&init_mm, pmd, kasan_zero_pte);
			continue;
		}

		if (pud_none(*pud)) {
			void *p = vmemmap_alloc_block(PAGE_SIZE, NUMA_NO_NODE);
			if (!p)
				return -ENOMEM;
			pud_populate(&init_mm, pud, p);
		}
		zero_pmd_populate(pud, addr, pud_addr_end(addr, end));
	} while (pud++, addr = next, addr != end);

	return ret;
}

static int __init zero_pgd_populate(unsigned long addr, unsigned long end)
{
	int ret = 0;
	pgd_t *pgd = pgd_offset_k(addr);
	unsigned long next;

	do {
		next = pgd_addr_end(addr, end);

		if (IS_ALIGNED(addr, PGDIR_SIZE) && end - addr >= PGDIR_SIZE) {
			pud_t *pud;
			pmd_t *pmd;

			pgd_populate(&init_mm, pgd, kasan_zero_pud);
			pud = pud_offset(pgd, addr);
			pud_populate(&init_mm, pud, kasan_zero_pmd);
			pmd = pmd_offset(pud, addr);
			pmd_populate_kernel(&init_mm, pmd, kasan_zero_pte);
			continue;
		}

		if (pgd_none(*pgd)) {
			void *p = vmemmap_alloc_block(PAGE_SIZE, NUMA_NO_NODE);
			if (!p)
				return -ENOMEM;
			pgd_populate(&init_mm, pgd, p);
		}
		zero_pud_populate(pgd, addr, next);
	} while (pgd++, addr = next, addr != end);

	return ret;
}

void __init kasan_populate_zero_shadow(const void *start, const void *end)
{
	if (zero_pgd_populate((unsigned long)start, (unsigned long)end))
		panic("kasan: unable to map zero shadow!");
}
