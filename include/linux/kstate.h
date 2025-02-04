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

	/* Marks the end of fields list */
	KS_END = (1UL << 31),
};

enum kstate_addr_type {
	KS_VMEMMAP_ADDR,
	KS_LINEAR_ADDR,
};

struct kstate_stream {
	void *start;
	void *pos;
	size_t size;
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
	KSTATE_LAST_ID = -1,
};

struct kstate_description {
	const char *name;
	enum kstate_ids id;
	atomic_t instance_id;
	int version_id;
	struct list_head state_list;

	const struct kstate_field *fields;
};

struct state_entry {
	u64 id;
	struct list_head list;
	struct kstate_description *kstd;
	void *obj;
};

extern int kstate_save_data(struct kstate_stream *stream, void *val, size_t size);

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

#ifdef CONFIG_KSTATE

void kstate_init(void);

int kstate_save_state(void);
void free_kstate_stream(void);

int kstate_register(struct kstate_description *state, void *obj);

struct kstate_entry;
int save_kstate(struct kstate_stream *stream, int id,
		const struct kstate_description *kstate,
		void *obj);
void restore_kstate(struct kstate_stream *stream, int id,
		const struct kstate_description *kstate, void *obj);
int kstate_load_migrate_buf(struct kimage *image);

#else

static inline void kstate_init(void) { }
#define kstate_register(state, obj)

static inline int kstate_save_state(void) { return 0; }
static inline void free_kstate_stream(void) { }

static inline int kstate_load_migrate_buf(struct kimage *image) { return 0; }
#endif


#define KSTATE_BASE_TYPE(_f, _state, _type) {		\
	.name = (__stringify(_f)),			\
	.size = sizeof(_type) + BUILD_BUG_ON_ZERO(	\
			!__same_type(typeof_member(_state, _f), _type)),\
	.flags = KS_BASE_TYPE,				\
	.offset = offsetof(_state, _f),			\
}

#define KSTATE_POINTER(_f, _state) {			\
		.name = (__stringify(_f)),		\
		.size = sizeof(*(((_state *)0)->_f)),	\
		.flags = KS_POINTER,			\
		.offset = offsetof(_state, _f),		\
	}

#define KSTATE_ADDRESS(_f, _state, _addr_type) {	\
		.name = (__stringify(_f)),		\
		.size = sizeof(*(((_state *)0)->_f)),	\
		.addr_type = (_addr_type),		\
		.flags = KS_ADDRESS,			\
		.offset = offsetof(_state, _f),		\
	}

#define KSTATE_END_OF_LIST() {	\
		.flags = KS_END,\
	}

#endif
