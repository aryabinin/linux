#ifndef _LINUX_KASAN_CHECKS_H
#define _LINUX_KASAN_CHECKS_H

#ifdef CONFIG_KASAN
void kasan_check_read(const void *p, size_t size);
void kasan_check_write(const void *p, size_t size);
#else
static inline void kasan_check_read(const void *p, size_t size) { }
static inline void kasan_check_write(const void *p, size_t size) { }
#endif

#endif
