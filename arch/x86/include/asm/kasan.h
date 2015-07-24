#ifndef _ASM_X86_KASAN_H
#define _ASM_X86_KASAN_H

#define KASAN_SHADOW_START      (0xffffec0000000000ULL)
/* 47 bits for kernel address -> (47 - 3) bits for shadow */
#define KASAN_SHADOW_END        (KASAN_SHADOW_START + (1ULL << (47 - 3)))

/*
 * This value is used to map an address to the corresponding shadow
 * address by the following formula:
 *	shadow_addr = (address >> 3) + KASAN_SHADOW_OFFSET;
 *
 * (1 << 61) shadow addresses - [KASAN_SHADOW_OFFSET,KASAN_SHADOW_END]
 * cover all 64-bits of virtual addresses. So KASAN_SHADOW_OFFSET
 * should satisfy the following equation:
 *      KASAN_SHADOW_OFFSET = KASAN_SHADOW_END - (1ULL << 61)
 */
#define KASAN_SHADOW_OFFSET (KASAN_SHADOW_END - (1UL << (64 - 3)))

#ifndef __ASSEMBLY__

#ifdef CONFIG_KASAN
void __init kasan_early_init(void);
void __init kasan_init(void);
#else
static inline void kasan_early_init(void) { }
static inline void kasan_init(void) { }
#endif

#endif

#endif
