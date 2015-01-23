#include <linux/kasan.h>
#include <linux/kernel.h>
#include <linux/memblock.h>
#include <linux/start_kernel.h>

#include <asm/page.h>
#include <asm/pgtable.h>
#include <asm/tlbflush.h>

static char kasan_zero_page[PAGE_SIZE] __page_aligned_bss;
static pgd_t tmp_page_table[PTRS_PER_PGD] __initdata __aligned(PAGE_SIZE);

#if CONFIG_PGTABLE_LEVELS > 3
static pud_t kasan_zero_pud[PTRS_PER_PUD] __page_aligned_bss;
#endif
#if CONFIG_PGTABLE_LEVELS > 2
static pmd_t kasan_zero_pmd[PTRS_PER_PMD] __page_aligned_bss;
#endif
static pte_t kasan_zero_pte[PTRS_PER_PTE] __page_aligned_bss;

static void __init create_pte(void)
{
	int i;

	for (i = 0; i < PTRS_PER_PTE; i++)
		set_pte(&kasan_zero_pte[i], __pte(__pa(kasan_zero_page)
							| PAGE_KERNEL));
}

static void __init create_pmd(void)
{
#if CONFIG_PGTABLE_LEVELS > 2
	int i;

	for (i = 0; i < PTRS_PER_PMD; i++)
		set_pmd(&kasan_zero_pmd[i], __pmd(__pa(kasan_zero_pte)
							| PAGE_KERNEL));
#endif
	create_pte();
}

static void __init create_pud(void)
{
#if CONFIG_PGTABLE_LEVELS > 3
	int i;

	for (i = 0; i < PTRS_PER_PUD; i++)
		set_pud(&kasan_zero_pud[i], __pud(__pa(kasan_zero_pmd)
							| PAGE_KERNEL));
#endif
	create_pmd();
}

#if CONFIG_PGTABLE_LEVELS > 3
void __init kasan_map_early_shadow(pgd_t *pgd)
{
	int i;
	unsigned long start = KASAN_SHADOW_START;
	unsigned long end = KASAN_SHADOW_END;

	for (i = pgd_index(start); start < end; i++) {
		set_pgd(&pgd[i], __pgd(__pa(kasan_zero_pud)
					| PAGE_KERNEL));
		start += PGDIR_SIZE;
	}
}
#elif CONFIG_PGTABLE_LEVELS > 2
void __init kasan_map_early_shadow(pgd_t *pgd)
{
	int i;
	unsigned long start = KASAN_SHADOW_START;
	unsigned long end = KASAN_SHADOW_END;

	for (i = pgd_index(start); start < end; i++) {
		set_pgd(&pgd[i], __pgd(__pa(kasan_zero_pmd)
					| PAGE_KERNEL));
		start += PGDIR_SIZE;
	}
}
#else
void __init kasan_map_early_shadow(pgd_t *pgd)
{
	int i;
	unsigned long start = KASAN_SHADOW_START;
	unsigned long end = KASAN_SHADOW_END;

	for (i = pgd_index(start); start < end; i++) {
		set_pgd(&pgd[i], __pgd(__pa(kasan_zero_pte)
					| PAGE_KERNEL));
		start += PGDIR_SIZE;
	}
}
#endif

void __init kasan_init(void)
{
	create_pud();
	kasan_map_early_shadow(swapper_pg_dir);
	kasan_map_early_shadow(idmap_pg_dir);
	flush_tlb_all();
	start_kernel();
}

#if CONFIG_PGTABLE_LEVELS == 4
static void __init clear_pgds(unsigned long start,
			unsigned long end)
{
	for (; start && start < end; start += PGDIR_SIZE)
		pgd_clear(pgd_offset_k(start));
}
#elif CONFIG_PGTABLE_LEVELS == 3
static void __init clear_pgds(unsigned long start,
			unsigned long end)
{
	for (; start && start < end; start += PGDIR_SIZE)
		pud_clear(pud_offset(pgd_offset_k(start), start));
}
#elif CONFIG_PGTABLE_LEVELS == 2
static void __init clear_pgds(unsigned long start,
			unsigned long end)
{
	for (; start && start < end; start += PGDIR_SIZE)
		pmd_clear(pmd_offset(pud_offset(pgd_offset_k(start), start), start));
}
#endif
static int __init zero_pte_populate(pmd_t *pmd, unsigned long addr,
				unsigned long end)
{
	pte_t *pte = pte_offset_kernel(pmd, addr);

	while (addr + PAGE_SIZE <= end) {
		set_pte(pte, __pte(__pa(kasan_zero_page)
					| PAGE_KERNEL_RO));
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
		set_pmd(pmd, __pmd(__pa(kasan_zero_pte)
					| PAGE_KERNEL_RO));
		addr += PMD_SIZE;
		pud = pud_offset(pgd_offset_k(addr), addr);
		pmd = pmd_offset(pud, addr);
	}

	if (addr < end) {
		if (pmd_none(*pmd)) {
			void *p = vmemmap_alloc_block(PAGE_SIZE, NUMA_NO_NODE);
			if (!p)
				return -ENOMEM;
			set_pmd(pmd, __pmd(__pa(p) | PAGE_KERNEL));
		}
		ret = zero_pte_populate(pmd, addr, end);
	}
	return ret;
}

#if CONFIG_PGTABLE_LEVELS > 2
static int __init zero_pud_populate(pgd_t *pgd, unsigned long addr,
				unsigned long end)
{
	int ret = 0;
	pud_t *pud = pud_offset(pgd, addr);

	while (IS_ALIGNED(addr, PUD_SIZE) && addr + PUD_SIZE <= end) {
		set_pud(pud, __pud(__pa(kasan_zero_pmd)
					| PAGE_KERNEL_RO));
		addr += PUD_SIZE;
		pgd = pgd_offset_k(addr);
		pud = pud_offset(pgd, addr);
	}

	if (addr < end) {
		if (pud_none(*pud)) {
			void *p = vmemmap_alloc_block(PAGE_SIZE, NUMA_NO_NODE);
			if (!p)
				return -ENOMEM;
			set_pud(pud, __pud(__pa(p) | PAGE_KERNEL));
		}
		ret = zero_pmd_populate(pud, addr, end);
	}
	return ret;
}
#else

static int __init zero_pud_populate(pgd_t *pgd, unsigned long addr,
				unsigned long end)
{
	pud_t *pud = pud_offset(pgd, addr);

	return zero_pmd_populate(pud, addr, end);
}
#endif

#if CONFIG_PGTABLE_LEVELS > 3
static int __init zero_pgd_populate(unsigned long addr, unsigned long end)
{
	int ret = 0;
	pgd_t *pgd = pgd_offset_k(addr);

	while (IS_ALIGNED(addr, PGDIR_SIZE) && addr + PGDIR_SIZE <= end) {
		set_pgd(pgd, __pgd(__pa(kasan_zero_pud)
					| PAGE_KERNEL_RO));
		addr += PGDIR_SIZE;
		pgd = pgd_offset_k(addr);
	}

	if (addr < end) {
		if (pgd_none(*pgd)) {
			void *p = vmemmap_alloc_block(PAGE_SIZE, NUMA_NO_NODE);
			if (!p)
				return -ENOMEM;
			set_pgd(pgd, __pgd(__pa(p) | PAGE_KERNEL));
		}
		ret = zero_pud_populate(pgd, addr, end);
	}
	return ret;
}
#else
static int __init zero_pgd_populate(unsigned long addr, unsigned long end)
{
	pgd_t *pgd = pgd_offset_k(addr);

	return zero_pud_populate(pgd, addr, end);
}
#endif

static void __init populate_zero_shadow(unsigned long start, unsigned long end)
{
	if (zero_pgd_populate(start, end))
		panic("kasan: unable to map zero shadow!");
}

static inline void cpu_set_ttbr1(unsigned long ttbr1)
{
	asm(
	"	msr	ttbr1_el1, %0\n"
	"	isb"
	:
	: "r" (ttbr1));
}

void __init kasan_mem_init(void)
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
				pfn_to_nid(__phys_to_pfn(start)));

	}

	memset(kasan_zero_page, 0, PAGE_SIZE);
	cpu_set_ttbr1(__pa(swapper_pg_dir));
	init_task.kasan_depth = 0;
}
