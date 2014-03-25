#ifndef __ASM_ARM_STRING_H
#define __ASM_ARM_STRING_H

/*
 * We don't do inline string functions, since the
 * optimised inline asm versions are not small.
 */

#define __HAVE_ARCH_STRRCHR
extern char * strrchr(const char * s, int c);

#define __HAVE_ARCH_STRCHR
extern char * strchr(const char * s, int c);

#define __HAVE_ARCH_MEMCPY
extern void * memcpy(void *, const void *, __kernel_size_t);

#define __HAVE_ARCH_MEMMOVE
extern void * memmove(void *, const void *, __kernel_size_t);

#define __HAVE_ARCH_MEMCHR
extern void * memchr(const void *, int, __kernel_size_t);

#define __HAVE_ARCH_MEMSET
extern void * memset(void *, int, __kernel_size_t);

extern void __memzero(void *ptr, __kernel_size_t n);

#define memset(p,v,n)							\
	({								\
	 	void *__p = (p); size_t __n = n;			\
		if ((__n) != 0) {					\
			if (__builtin_constant_p((v)) && (v) == 0)	\
				__memzero((__p),(__n));			\
			else						\
				memset((__p),(v),(__n));		\
		}							\
		(__p);							\
	})


#if defined(CONFIG_KASAN) && defined(KASAN_HOOKS)

/*
 * Since some of the following functions (memset, memmove, memcpy)
 * are written in assembly, compiler can't instrument memory accesses
 * inside them.
 *
 * To solve this issue we replace these functions with our own instrumented
 * functions (kasan_mem*)
 *
 * In case if any of mem*() fucntions are written in C we use our instrumented
 * functions for perfomance reasons. It's should be faster to check whole
 * accessed memory range at once, then do a lot of checks at each memory access.
 *
 * In rare circumstances you may need to use the original functions,
 * in such case #undef KASAN_HOOKS before includes.
 */
#undef memset

void *kasan_memset(void *ptr, int val, size_t len);
void *kasan_memcpy(void *dst, const void *src, size_t len);
void *kasan_memmove(void *dst, const void *src, size_t len);

#define memcpy(dst, src, len) kasan_memcpy((dst), (src), (len))
#define memset(ptr, val, len) kasan_memset((ptr), (val), (len))
#define memmove(dst, src, len) kasan_memmove((dst), (src), (len))

#endif /* CONFIG_KASAN && KASAN_HOOKS */

#endif
