#include <linux/kasan.h>
#include <linux/kernel.h>
#include <linux/memblock.h>
#include <linux/start_kernel.h>

#include <asm/page.h>
#include <asm/pgalloc.h>
#include <asm/pgtable.h>
#include <asm/tlbflush.h>

unsigned char kasan_zero_page[PAGE_SIZE] __page_aligned_bss;
static pgd_t tmp_page_table[PTRS_PER_PGD] __initdata __aligned(PAGE_SIZE);

#if CONFIG_PGTABLE_LEVELS > 3
pud_t kasan_zero_pud[PTRS_PER_PUD] __page_aligned_bss;
#endif
#if CONFIG_PGTABLE_LEVELS > 2
pmd_t kasan_zero_pmd[PTRS_PER_PMD] __page_aligned_bss;
#endif
pte_t kasan_zero_pte[PTRS_PER_PTE] __page_aligned_bss;

static void __init kasan_early_pmd_populate(unsigned long start, unsigned long end, pud_t *pud)
{
	unsigned long addr;
	unsigned long next;
	pmd_t *pmd;

	pmd = pmd_offset(pud, start);
	for (addr = start; addr < end;) {
		pmd_populate_kernel(&init_mm, pmd, kasan_zero_pte);
		next = pmd_addr_end(addr, end);
		addr = next;
		pmd++;
	}
}

static void __init kasan_early_pud_populate(unsigned long start, unsigned long end, pgd_t *pgd)
{
	unsigned long addr;
	unsigned long next;
	pud_t *pud;

	pud = pud_offset(pgd, start);
	for (addr = start; addr < end;) {
		pud_populate(&init_mm, pud, kasan_zero_pmd);
		next = pud_addr_end(addr, end);
		kasan_early_pmd_populate(addr, next, pud);
		addr = next;
		pud++;
	}
}

void __init kasan_map_early_shadow(pgd_t *pgdp)
{
	int i;
	unsigned long start = KASAN_SHADOW_START;
	unsigned long end = KASAN_SHADOW_END;
	unsigned long addr;
	unsigned long next;
	pgd_t *pgd;

	for (i = 0; i < PTRS_PER_PTE; i++)
		set_pte(&kasan_zero_pte[i], pfn_pte(
				virt_to_pfn(kasan_zero_page), PAGE_KERNEL));

	pgd = pgd_offset_k(start);
	for (addr = start; addr < end;) {
		pgd_populate(&init_mm, pgd, kasan_zero_pud);
		next = pgd_addr_end(addr, end);
		kasan_early_pud_populate(addr, next, pgd);
		addr = next;
		pgd++;
	}
}

void __init kasan_early_init(void)
{
	kasan_map_early_shadow(swapper_pg_dir);
	start_kernel();
}

static void __init clear_pgds(unsigned long start,
			unsigned long end)
{
	for (; start && start < end; start += PGDIR_SIZE)
		set_pgd(pgd_offset_k(start), __pgd(0));
}

static void cpu_set_ttbr1(unsigned long ttbr1)
{
	asm(
	"	msr	ttbr1_el1, %0\n"
	"	isb"
	:
	: "r" (ttbr1));
}

void __init kasan_init(void)
{
	struct memblock_region *reg;

	memcpy(tmp_page_table, swapper_pg_dir, sizeof(tmp_page_table));
	cpu_set_ttbr1(__pa(tmp_page_table));

	clear_pgds(KASAN_SHADOW_START, KASAN_SHADOW_END);

	populate_zero_shadow(KASAN_SHADOW_START,
			(unsigned long)kasan_mem_to_shadow((void *)MODULES_VADDR));

	for_each_memblock(memory, reg) {
		void *start = (void *)__phys_to_virt(reg->base);
		void *end = (void *)__phys_to_virt(reg->base + reg->size);

		if (start >= end)
			break;

		vmemmap_populate((unsigned long)kasan_mem_to_shadow(start),
				(unsigned long)kasan_mem_to_shadow(end),
				pfn_to_nid(virt_to_pfn(start)));
	}

	memset(kasan_zero_page, 0, PAGE_SIZE);
	cpu_set_ttbr1(__pa(swapper_pg_dir));
	init_task.kasan_depth = 0;
}
