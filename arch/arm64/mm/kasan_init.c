#include <linux/kernel.h>

char poisoned_page[PAGE_SIZE];

void __init kasan_map_early_shadow(pgd_t *pgd)
{
	int i;
	unsigned long start = KASAN_SHADOW_START;
	unsigned long end = KASAN_SHADOW_END;

	for (i = pgd_index(start); start < end; i++) {
		pgd[i] = __pgd(__pa_nodebug(kasan_poisoned_pud)
				| PAGE_KERNEL);
		start += PGDIR_SIZE;
	}
}


void __init kasan_init(void)
{
	
}
