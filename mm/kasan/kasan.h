#ifndef __MM_KASAN_KASAN_H
#define __MM_KASAN_KASAN_H

#include <linux/kasan.h>

#define KASAN_SHADOW_SCALE_SIZE (1UL << KASAN_SHADOW_SCALE_SHIFT)
#define KASAN_SHADOW_MASK       (KASAN_SHADOW_SCALE_SIZE - 1)

struct access_info {
	unsigned long access_addr;
	unsigned long first_bad_addr;
	size_t access_size;
	bool is_write;
	unsigned long ip;
};

void kasan_report_error(struct access_info *info);
void kasan_report_user_access(struct access_info *info);

static inline unsigned long kasan_shadow_to_mem(unsigned long shadow_addr)
{
	return (shadow_addr - KASAN_SHADOW_OFFSET) << KASAN_SHADOW_SCALE_SHIFT;
}

static inline bool kasan_enabled(void)
{
	return !current->kasan_depth;
}

static __always_inline void kasan_report(unsigned long addr,
					size_t size,
					bool is_write)
{
	struct access_info info;

	if (likely(!kasan_enabled()))
		return;

	info.access_addr = addr;
	info.access_size = size;
	info.is_write = is_write;
	info.ip = _RET_IP_;
	kasan_report_error(&info);
}


#endif
