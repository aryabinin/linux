#ifndef _LINUX_KASAN_CHECKS_H

#include <linux/types.h>

#ifdef __SANITIZE_ADDRESS__
void kasan_check_read(const void *p, size_t size);
void kasan_check_write(const void *p, size_t size);
#else
#define kasan_check_read(p, size) do { } while (0)
#define kasan_check_write(p, size) do { } while (0)
#endif

#endif
