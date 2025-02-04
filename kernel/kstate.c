// SPDX-License-Identifier: GPL-2.0-only
#include <linux/ctype.h>
#include <linux/kexec.h>
#include <linux/kstate.h>
#include <linux/memblock.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/vmalloc.h>

static LIST_HEAD(states);

struct kstate_entry {
	int state_id;
	int version_id;
	int instance_id;
	int size;
	DECLARE_FLEX_ARRAY(u8, data);
};

struct kstate_stream kstate_stream;

static unsigned long get_addr_offset(const struct kstate_field *field)
{
	switch (field->addr_type) {
	case KS_VMEMMAP_ADDR:
		return VMEMMAP_START;
	case KS_LINEAR_ADDR:
		return PAGE_OFFSET;
	default:
		WARN_ON(1);
	}
	return 0;
}

static int alloc_space(struct kstate_stream *stream, size_t size)
{
	void *new_start;
	size_t new_size;
	size_t cur_size = stream->pos - stream->start;

	size = size + 4; /* Always alloc extra for KSTATE_LAST_ID */
	if (cur_size + size < stream->size)
		return 0;

	new_size = PAGE_ALIGN(cur_size + size);

	new_start = vrealloc(stream->start, new_size, GFP_KERNEL);
	if (!new_start)
		return -ENOMEM;

	stream->start = new_start;
	stream->size = new_size;
	stream->pos = stream->start + cur_size;
	return 0;
}

int kstate_save_data(struct kstate_stream *stream, void *val, size_t size)
{
	int ret;

	ret = alloc_space(stream, size);
	if (ret)
		return ret;
	memcpy(stream->pos, val, size);
	stream->pos += size;
	return 0;
}

int save_kstate(struct kstate_stream *stream, int id,
		const struct kstate_description *kstate,
		void *obj)
{
	const struct kstate_field *field = kstate->fields;
	struct kstate_entry *ke;
	unsigned long ke_off;
	int ret = 0;

	ret = alloc_space(stream, sizeof(*ke));
	if (ret)
		goto err;

	ke_off = stream->pos - stream->start;
	ke = stream->pos;
	stream->pos += sizeof(*ke);

	ke->state_id = kstate->id;
	ke->version_id = kstate->version_id;
	ke->instance_id = id;

	while (field->flags != KS_END) {
		void *first,  *cur;
		int n_elems = 1;
		int size, i;

		first = obj + field->offset;

		if (field->flags & KS_POINTER)
			first = *(void **)(obj + field->offset);
		if (field->count)
			n_elems = field->count();
		size = field->size;
		for (i = 0; i < n_elems; i++) {
			cur = first + i * size;

			if (field->flags & KS_ARRAY_OF_POINTER)
				cur = *(void **)cur;

			if (field->flags & KS_STRUCT) {
				ret = save_kstate(stream, 0, field->ksd, cur);
				if (ret)
					goto err;
			} else if (field->flags & KS_CUSTOM) {
				if (field->save) {
					ret = field->save(stream, cur, field);
					if (ret)
						goto err;
				}
			} else if (field->flags & (KS_BASE_TYPE|KS_POINTER)) {
				ret = kstate_save_data(stream, cur, size);
				if (ret)
					goto err;
			} else if (field->flags & KS_ADDRESS) {
				void *addr_offset = *(void **)cur
					- get_addr_offset(field);
				ret = kstate_save_data(stream, &addr_offset,
						sizeof(addr_offset));
				if (ret)
					goto err;
			} else
				WARN_ON_ONCE(1);
		}
		field++;

	}

	ke = stream->start + ke_off;
	ke->size = (stream->pos - stream->start) - (ke_off + sizeof(*ke));
err:
	if (ret)
		pr_err("kstate: save of state %s failed\n", kstate->name);

	return ret;
}

static int alloc_kstate_stream(void)
{
	size_t size = PAGE_SIZE;
	void *buf;

	buf = vzalloc(size);
	if (!buf)
		return -ENOMEM;

	kstate_stream.size = size;
	kstate_stream.start = kstate_stream.pos = buf;
	return 0;
}

void free_kstate_stream(void)
{
	vfree(kstate_stream.start);
	kstate_stream.start = NULL;
	kstate_stream.size = 0;
}

int kstate_save_state(void)
{
	struct state_entry *se;
	struct kstate_entry *ke;
	int ret;

	ret = alloc_kstate_stream();
	if (ret)
		return ret;

	list_for_each_entry(se, &states, list) {
		ret = save_kstate(&kstate_stream, se->id, se->kstd, se->obj);
		if (ret)
			return ret;
	}
	ke = kstate_stream.pos;
	ke->state_id = KSTATE_LAST_ID;
	return 0;
}

int kstate_load_migrate_buf(struct kimage *image)
{
	int ret;
	struct kexec_buf kbuf = { .image = image, .buf_min = 0,
		.buf_max = ULONG_MAX, .top_down = true };

	kbuf.bufsz = kstate_stream.size;
	kbuf.buffer = kstate_stream.start;

	kbuf.memsz = kstate_stream.size;

	kbuf.buf_align = PAGE_SIZE;
	kbuf.mem = KEXEC_BUF_MEM_UNKNOWN;
	ret = kexec_add_buffer(&kbuf);
	if (ret)
		return ret;
	image->kstate_stream_addr = kbuf.mem;
	image->kstate_size = kstate_stream.size;

	pr_info("kstate: Loaded mig_stream at 0x%lx bufsz=0x%lx memsz=0x%lx\n",
		kbuf.mem, kbuf.bufsz, kbuf.memsz);

	return ret;
}

void restore_kstate(struct kstate_stream *stream, int id,
		const struct kstate_description *kstate, void *obj)
{
	const struct kstate_field *field = kstate->fields;
	struct kstate_entry *ke = stream->pos;
	stream->pos = ke->data;

	WARN_ONCE(ke->version_id != kstate->version_id, "version mismatch %d %d\n",
		ke->version_id, kstate->version_id);

	WARN_ONCE(ke->instance_id != id, "instance id mismatch %d %d\n",
		ke->instance_id, id);

	while (field->flags != KS_END) {
		void *first, *cur;
		int n_elems = 1;
		int size, i;

		first = obj + field->offset;
		if (field->flags & KS_POINTER)
			first = *(void **)(obj + field->offset);
		if (field->count)
			n_elems = field->count();
		size = field->size;
		for (i = 0; i < n_elems; i++) {
			cur = first + i * size;

			if (field->flags & KS_ARRAY_OF_POINTER)
				cur = *(void **)cur;

			if (field->flags & KS_STRUCT)
				restore_kstate(stream, 0, field->ksd, cur);
			else if (field->flags & KS_CUSTOM) {
				if (field->restore)
					field->restore(stream, cur, field);
			} else if (field->flags & (KS_BASE_TYPE | KS_POINTER)) {
				memcpy(cur, stream->pos, size);
				stream->pos += size;
			} else if (field->flags & KS_ADDRESS) {
				*(void **)cur = (*(void **)stream->pos) +
					get_addr_offset(field);
				stream->pos += sizeof(void *);
			} else
				WARN_ON_ONCE(1);

		}
		field++;
	}
}

static void restore_migrate_state(unsigned long kstate_data,
				struct state_entry *se)
{
	struct kstate_stream stream;
	struct kstate_entry *ke;

	if (kstate_data == -1)
		return;

	ke = (struct kstate_entry *)phys_to_virt(kstate_data);
	if (WARN_ON_ONCE(ke->state_id == 0))
		return;

	stream.start = stream.pos = ke;
	while (ke->state_id != KSTATE_LAST_ID) {
		if (ke->state_id != se->kstd->id ||
		    ke->instance_id != se->id) {
			ke = (struct kstate_entry *)(ke->data + ke->size);
			continue;
		}
		stream.pos = ke;
		restore_kstate(&stream, se->id, se->kstd, se->obj);
		ke = (struct kstate_entry *)(ke->data + ke->size);
	}
}

static unsigned long kstate_stream_addr = -1;
static unsigned long kstate_size;

static void __kstate_register(struct kstate_description *state, void *obj,
			struct state_entry *se)
{
	se->kstd = state;
	se->id = atomic_inc_return(&state->instance_id);
	se->obj = obj;
	list_add(&se->list, &states);
	restore_migrate_state(kstate_stream_addr, se);
}

int kstate_register(struct kstate_description *state, void *obj)
{
	struct state_entry *se;

	se = kmalloc(sizeof(*se), GFP_KERNEL);
	if (!se)
		return -ENOMEM;

	__kstate_register(state, obj, se);
	return 0;
}

static int __init setup_kstate(char *arg)
{
	char *end;

	if (!arg)
		return -EINVAL;
	kstate_stream_addr = memparse(arg, &end);
	if (*end == '@')
		kstate_size = memparse(end + 1, &end);

	return end > arg ? 0 : -EINVAL;
}
early_param("kstate_stream", setup_kstate);

void __init kstate_init(void)
{
	memblock_reserve(kstate_stream_addr, kstate_size);
}
