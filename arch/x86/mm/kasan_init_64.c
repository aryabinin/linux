#include <linux/bootmem.h>
#include <linux/kasan.h>
#include <linux/kdebug.h>
#include <linux/mm.h>
#include <linux/pfn.h>
#include <linux/sched.h>
#include <linux/vmalloc.h>

#include <asm/pgalloc.h>
#include <asm/tlbflush.h>
#include <asm/sections.h>

extern pgd_t early_level4_pgt[PTRS_PER_PGD];
extern struct range pfn_mapped[E820_X_MAX];

static pud_t kasan_zero_pud[PTRS_PER_PUD] __page_aligned_bss;
static pmd_t kasan_zero_pmd[PTRS_PER_PMD] __page_aligned_bss;
static pte_t kasan_zero_pte[PTRS_PER_PTE] __page_aligned_bss;

/*
 * This page used as early shadow. We don't use empty_zero_page
 * at early stages, stack instrumentation could write some garbage
 * to this page.
 * Latter we reuse it as zero shadow for large ranges of memory
 * that allowed to access, but not instrumented by kasan
 * (vmalloc/vmemmap ...).
 */
static unsigned char kasan_zero_page[PAGE_SIZE] __page_aligned_bss;

static int __init map_range(struct range *range)
{
	unsigned long start;
	unsigned long end;

	start = (unsigned long)kasan_mem_to_shadow(pfn_to_kaddr(range->start));
	end = (unsigned long)kasan_mem_to_shadow(pfn_to_kaddr(range->end));

	/*
	 * end + 1 here is intentional. We check several shadow bytes in advance
	 * to slightly speed up fastpath. In some rare cases we could cross
	 * boundary of mapped shadow, so we just map some more here.
	 */
	return vmemmap_populate(start, end + 1, NUMA_NO_NODE);
}

static void __init clear_pgds(unsigned long start,
			unsigned long end)
{
	for (; start < end; start += PGDIR_SIZE)
		pgd_clear(pgd_offset_k(start));
}

static void __init kasan_map_early_shadow(pgd_t *pgd)
{
	int i;
	unsigned long start = KASAN_SHADOW_START;
	unsigned long end = KASAN_SHADOW_END;

	for (i = pgd_index(start); start < end; i++) {
		pgd[i] = __pgd(__pa_nodebug(kasan_zero_pud)
				| _KERNPG_TABLE);
		start += PGDIR_SIZE;
	}
}

static __init void *early_alloc(size_t size, int node)
{
	return memblock_virt_alloc_try_nid(size, size, __pa(MAX_DMA_ADDRESS),
					BOOTMEM_ALLOC_ACCESSIBLE, node);
}

static int __init zero_pte_populate(pmd_t *pmd, unsigned long addr,
				unsigned long end)
{
	pte_t *pte = pte_offset_kernel(pmd, addr);
	pte_t zero_pte;

	zero_pte = pfn_pte(PFN_DOWN(__pa(kasan_zero_page)), PAGE_KERNEL);
	zero_pte = pte_wrprotect(zero_pte);

	while (addr + PAGE_SIZE <= end) {
		set_pte_at(&init_mm, addr, pte, zero_pte);
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
			void *p = early_alloc(PAGE_SIZE, NUMA_NO_NODE);
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
			void *p = early_alloc(PAGE_SIZE, NUMA_NO_NODE);
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

			/*
			 * kasan_zero_pud should be populated with pmds
			 * at this moment.
			 * [pud,pmd]_populate*() bellow needed only for
			 * 3,2 - level page tables where we don't have
			 * puds,pmds, so pgd_populate(), pud_populate()
			 * is noops.
			 */
			pgd_populate(&init_mm, pgd, kasan_zero_pud);
			pud = pud_offset(pgd, addr);
			pud_populate(&init_mm, pud, kasan_zero_pmd);
			pmd = pmd_offset(pud, addr);
			pmd_populate_kernel(&init_mm, pmd, kasan_zero_pte);
			continue;
		}

		if (pgd_none(*pgd)) {
			void *p = early_alloc(PAGE_SIZE, NUMA_NO_NODE);
			if (!p)
				return -ENOMEM;
			pgd_populate(&init_mm, pgd, p);
		}
		zero_pud_populate(pgd, addr, next);
	} while (pgd++, addr = next, addr != end);

	return ret;
}

static void __init populate_zero_shadow(const void *start, const void *end)
{
	if (zero_pgd_populate((unsigned long)start, (unsigned long)end))
		panic("kasan: unable to map zero shadow!");
}

#ifdef CONFIG_KASAN_INLINE
static int kasan_die_handler(struct notifier_block *self,
			     unsigned long val,
			     void *data)
{
	if (val == DIE_GPF) {
		pr_emerg("CONFIG_KASAN_INLINE enabled");
		pr_emerg("GPF could be caused by NULL-ptr deref or user memory access");
	}
	return NOTIFY_OK;
}

static struct notifier_block kasan_die_notifier = {
	.notifier_call = kasan_die_handler,
};
#endif

void __init kasan_early_init(void)
{
	int i;
	pteval_t pte_val = __pa_nodebug(kasan_zero_page) | __PAGE_KERNEL;
	pmdval_t pmd_val = __pa_nodebug(kasan_zero_pte) | _KERNPG_TABLE;
	pudval_t pud_val = __pa_nodebug(kasan_zero_pmd) | _KERNPG_TABLE;

	for (i = 0; i < PTRS_PER_PTE; i++)
		kasan_zero_pte[i] = __pte(pte_val);

	for (i = 0; i < PTRS_PER_PMD; i++)
		kasan_zero_pmd[i] = __pmd(pmd_val);

	for (i = 0; i < PTRS_PER_PUD; i++)
		kasan_zero_pud[i] = __pud(pud_val);

	kasan_map_early_shadow(early_level4_pgt);
	kasan_map_early_shadow(init_level4_pgt);
}

void __init kasan_init(void)
{
	int i;

#ifdef CONFIG_KASAN_INLINE
	register_die_notifier(&kasan_die_notifier);
#endif

	memcpy(early_level4_pgt, init_level4_pgt, sizeof(early_level4_pgt));
	load_cr3(early_level4_pgt);

	clear_pgds(KASAN_SHADOW_START, KASAN_SHADOW_END);

	populate_zero_shadow((void *)KASAN_SHADOW_START,
			kasan_mem_to_shadow((void *)PAGE_OFFSET));

	for (i = 0; i < E820_X_MAX; i++) {
		if (pfn_mapped[i].end == 0)
			break;

		if (map_range(&pfn_mapped[i]))
			panic("kasan: unable to allocate shadow!");
	}
	populate_zero_shadow(kasan_mem_to_shadow((void *)PAGE_OFFSET + MAXMEM),
			kasan_mem_to_shadow((void *)__START_KERNEL_map));

	vmemmap_populate((unsigned long)kasan_mem_to_shadow(_stext),
			(unsigned long)kasan_mem_to_shadow(_end),
			NUMA_NO_NODE);

	populate_zero_shadow(kasan_mem_to_shadow((void *)MODULES_END),
			(void *)KASAN_SHADOW_END);

	memset(kasan_zero_page, 0, PAGE_SIZE);

	load_cr3(init_level4_pgt);
	init_task.kasan_depth = 0;
}
