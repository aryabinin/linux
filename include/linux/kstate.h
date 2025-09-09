/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _KSTATE_H
#define _KSTATE_H

#include <linux/atomic.h>
#include <linux/build_bug.h>
#include <linux/list.h>
#include <linux/stringify.h>

struct kstate_description;
struct kstate_stream;
struct kimage;

enum kstate_flags {

	/*
	 * The struct member at 'obj + kstate_field.offset' is some basic
	 * type, just copy it by value. The size is kstate_field->size.
	 */

	KS_BASE_TYPE = (1 << 0),

	/*
	 * The struct member at 'obj + kstate_field.offset' is a pointer
	 * to the actual data (e.g. struct a { int *b; }).
	 * save_kstate() will dereference the pointer to get the actual data
	 * and store it to the stream. restore_kstate() will copy the data from
	 * the stream to wherever the pointer points to.
	 */
	KS_POINTER = (1 << 1),

	/*
	 * The struct member at 'obj + kstate_field.offset' is another struct.
	 * kstate_field->ksd points to 'kstate_description' of that struct.
	 */
	KS_STRUCT = (1 << 2),

	/*
	 * Some non-trivial field that requires custom kstate_field->save()
	 * ->restore() callbacks to save/restore data.
	 */
	KS_CUSTOM = (1 << 3),

	/*
	 * The field is a array of kstate_field->count() pointers
	 * (e.g. struct a { uint8_t *b[]; }). Dereference each array entry
	 * before store/restore data.
	 */
	KS_ARRAY_OF_POINTER = (1 << 4),

	/*
	 * The field is a pointer to vmemmap or linear memory (determined by
	 * kstate_field->addr_type). This is used for pointers to persistent
	 * pages/data. Store offset from the start of the area instead of
	 * pointer itself, so we could defeat KASLR on restore phase (by adding
	 * new kernel's corresponding offset).
	 */
	KS_ADDRESS = (1 << 5),

	/*
	 * The field used to exist in older versions. kstate_field->version_id
	 * is latest version that have this field.
	 */
	KS_DEPRECATED = (1 << 6),

	/* Marks the end of fields list */
	KS_END = (1UL << 31),
};

enum kstate_addr_type {
	KS_VMEMMAP_ADDR,
	KS_LINEAR_ADDR,
};

struct kstate_stream {
	void *pos;
	struct folio *folio;
};

struct kstate_field {
	const char *name;
	size_t offset;
	size_t size;
	enum kstate_flags flags;
	const struct kstate_description *ksd;
	enum kstate_addr_type addr_type;
	int version_id;
	int (*restore)(struct kstate_stream *stream, void *obj,
		const struct kstate_field *field);
	int (*save)(struct kstate_stream *stream, void *obj,
		const struct kstate_field *field);
	int (*count)(void);
};

enum kstate_ids {
	KSTATE_FOLIO_ID = 1,
	KSTATE_KHO_FDT_ID,
	KSTATE_LAST_ID = -1,
};

struct kstate_description {
	const char *name;
	enum kstate_ids id;
	atomic_t instance_id;
	int version_id;
	int min_version_id;

	const struct kstate_field *fields;
	const struct kstate_description **subsections;
};

struct state_entry {
	u64 id;
	struct list_head list;
	struct kstate_description *kstd;
	void *obj;
};

static inline bool kstate_get_byte(struct kstate_stream *stream)
{
	bool ret = *(u8 *)stream->pos;

	stream->pos++;
	return ret;
}

static inline unsigned long kstate_get_ulong(struct kstate_stream *stream)
{
	unsigned long ret = *(unsigned long *)stream->pos;

	stream->pos += sizeof(unsigned long);
	return ret;
}

extern struct kstate_description page_state;

#ifdef CONFIG_KSTATE

extern phys_addr_t kstate_out_paddr;

int kstate_save_state(void);
void free_kstate_stream(void);

int kstate_save_data(struct kstate_stream *stream, const void *val,
		size_t size);
void kstate_restore_data(struct kstate_stream *stream, void *val, size_t size);
int kstate_register(struct kstate_description *state, void *obj, int id);
void kstate_unregister(struct kstate_description *state, void *obj, int id);
int kstate_restore(struct kstate_description *state, void *obj, int id);
int kstate_register_restore(struct kstate_description *state, void *obj);

struct kstate_entry;

int kstate_folio_save(struct kstate_stream *stream, void *obj,
		const struct kstate_field *field);
int kstate_folio_restore(struct kstate_stream *stream, void *obj,
		const struct kstate_field *field);

int kstate_abort(void);
int kstate_finalize(void);

int kstate_early_init(phys_addr_t kstate_entries, u64 len);

#else

#define kstate_register(state, obj)

static inline int kstate_save_data(struct kstate_stream *stream,
				const void *val, size_t size)
{
	return 0;
}
static inline void kstate_restore_data(struct kstate_stream *stream, void *val,
				size_t size)
{
}

#endif

#define KSTATE_BASE_TYPE_V(_f, _state, _type, _v) {	\
	.name = (__stringify(_f)),			\
	.version_id = (_v),				\
	.size = sizeof(_type) + BUILD_BUG_ON_ZERO(	\
			!__same_type(typeof_member(_state, _f), _type)),\
	.flags = KS_BASE_TYPE,				\
	.offset = offsetof(_state, _f),			\
}

#define KSTATE_BASE_TYPE(_f, _state, _type) \
	KSTATE_BASE_TYPE_V(_f, _state, _type, 0)

#define KSTATE_BASE_TYPE_DEPRECATED(_f, _type, _v) {	\
	.name = (__stringify(_f)),			\
	.version_id = (_v),				\
	.size = sizeof(_type),				\
	.flags = KS_DEPRECATED,				\
}

#define KSTATE_POINTER_V(_f, _state, _v) {		\
		.name = (__stringify(_f)),		\
		.version_id = (_v),			\
		.size = sizeof(*(((_state *)0)->_f)),	\
		.flags = KS_POINTER,			\
		.offset = offsetof(_state, _f),		\
	}

#define KSTATE_POINTER(_f, _state) KSTATE_POINTER_V(_f, _state, 0)

#define KSTATE_ADDRESS_V(_f, _state, _addr_type, _v) {	\
		.name = (__stringify(_f)),		\
		.version_id = (_v),			\
		.size = sizeof(*(((_state *)0)->_f)),	\
		.addr_type = (_addr_type),		\
		.flags = KS_ADDRESS,			\
		.offset = offsetof(_state, _f),		\
	}
#define KSTATE_ADDRESS(_f, _state, _addr_type)		\
	KSTATE_ADDRESS_V(_f, _state, _addr_type, 0)

#define KSTATE_FOLIO(_f, _state) {			\
		.name = "folio",			\
		.flags = KS_CUSTOM,			\
		.offset = offsetof(_state, _f),		\
		.save = kstate_folio_save,		\
		.restore = kstate_folio_restore,	\
	}

#define KSTATE_END_OF_LIST() {		\
		.flags = KS_END,	\
	}

#endif
