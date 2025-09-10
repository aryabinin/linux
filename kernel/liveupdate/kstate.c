// SPDX-License-Identifier: GPL-2.0-only
#include <linux/ctype.h>
#include <linux/gfp.h>
#include <linux/kexec.h>
#include <linux/kexec_handover.h>
#include <linux/kstate.h>
#include <linux/memblock.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/vmalloc.h>

#define KSTATE_MAGIC 0x3B37778C

static DEFINE_MUTEX(states_lock);
static LIST_HEAD(states);

phys_addr_t kstate_out_paddr;

void *kstate_stream_addr;

struct kstate_entry {
	int section_type;
	int state_id;
	int version_id;
	int instance_id;
	int size;
	DECLARE_FLEX_ARRAY(u8, data);
};

struct kstate_stream kstate_stream;

enum {
	KS_SUBSECTION = 1,
	KS_SECTION,
	KS_EOF = -1,
};

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

static struct folio *folio_realloc(struct folio *folio, int new_order,
				gfp_t gfp_mask)
{
	struct folio *new_folio = folio_alloc(GFP_KERNEL, new_order);

	if (!new_folio)
		return NULL;

	memcpy(folio_address(new_folio), folio_address(folio), folio_size(folio));
	folio_put(folio);
	return new_folio;
}

static int alloc_space(struct kstate_stream *stream, size_t size)
{
	int new_order;
	struct folio *new_folio;
	size_t cur_size = stream->pos - folio_address(stream->folio);

	size = size + 4; /* Always alloc extra for KS_EOF */
	if (cur_size + size < folio_size(stream->folio))
		return 0;

	new_order = get_order(cur_size) + 1;

	new_folio = folio_realloc(stream->folio, new_order, GFP_KERNEL);
	if (!new_folio)
		return -ENOMEM;

	stream->folio = new_folio;
	stream->pos = folio_address(stream->folio) + cur_size;
	return 0;
}

int kstate_save_data(struct kstate_stream *stream, const void *val,
			size_t size)
{
	int ret;

	ret = alloc_space(stream, size);
	if (ret)
		return ret;
	memcpy(stream->pos, val, size);
	stream->pos += size;
	return 0;
}

static int save_kstate(struct kstate_stream *stream, int id,
		const struct kstate_description *kstate,
		void *obj, int section_type)
{
	const struct kstate_field *field = kstate->fields;
	struct kstate_entry *ke;
	unsigned long ke_off;
	int ret = 0;

	ret = alloc_space(stream, sizeof(*ke));
	if (ret)
		goto err;

	ke_off = stream->pos - folio_address(stream->folio);
	ke = stream->pos;
	stream->pos += sizeof(*ke);

	ke->section_type = section_type;
	ke->state_id = kstate->id;
	ke->version_id = kstate->version_id;
	ke->instance_id = id;

	while (field->flags != KS_END) {
		void *first, *cur;
		int n_elems = 1;
		int size, i;

		first = obj + field->offset;
		/* Fields of higher versions shouldn't exist */
		if (WARN_ON(field->version_id > kstate->version_id)) {
			field++;
			continue;
		}
		if (field->flags & KS_DEPRECATED) {
			field++;
			continue;
		}

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
				ret = save_kstate(stream, 0, field->ksd, cur, section_type);
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

	ke = folio_address(stream->folio) + ke_off;
	ke->size = (stream->pos - folio_address(stream->folio)) - (ke_off + sizeof(*ke));
err:
	if (ret)
		pr_err("kstate: save of state %s failed\n", kstate->name);

	return ret;
}

static int save_kstates(struct kstate_stream *stream, int id,
		const struct kstate_description *kstate,
		void *obj)
{
	int ret = 0;
	const struct kstate_description *const *section;

	ret = save_kstate(stream, id, kstate, obj, KS_SECTION);
	if (ret)
		return ret;

	if (!kstate->subsections)
		return ret;

	section = kstate->subsections;
	while (*section) {
		ret = save_kstate(stream, id, *section, obj, KS_SUBSECTION);
		if (ret)
			break;
		section++;
	}

	return ret;
}

static int alloc_kstate_stream(void)
{
	struct folio *folio;
	u32 *buf;

	folio = folio_alloc(GFP_KERNEL, 0);
	if (!folio)
		return -ENOMEM;

	buf = folio_address(folio);
	*buf++ = KSTATE_MAGIC;
	kstate_stream.pos = buf;
	kstate_stream.folio = folio;
	return 0;
}

void free_kstate_stream(void)
{
	if (kstate_stream.folio)
		folio_put(kstate_stream.folio);

	kstate_stream.folio = NULL;
	kstate_stream.pos = NULL;
}

int kstate_save_state(void)
{
	struct state_entry *se;
	struct kstate_entry *ke;
	int err = 0;

	err = alloc_kstate_stream();
	if (err)
		return err;

	mutex_lock(&states_lock);
	list_for_each_entry(se, &states, list) {
		err = save_kstates(&kstate_stream, se->id, se->kstd, se->obj);
		if (err)
			goto out;
	}
	ke = kstate_stream.pos;
	ke->section_type = KS_EOF;
out:
	mutex_unlock(&states_lock);
	if (err)
		free_kstate_stream();
	return err;
}

void kstate_restore_data(struct kstate_stream *stream, void *val, size_t size)
{
	memcpy(val, stream->pos, size);
	stream->pos += size;
}

static void restore_kstate(struct kstate_stream *stream, int id,
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

		if (field->version_id > ke->version_id) {
			field++;
			continue;
		}
		if (field->flags & KS_DEPRECATED) {
			if (ke->version_id <= field->version_id)
				stream->pos += field->size;
			field++;
			continue;
		}

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

static struct kstate_entry *find_subsection(struct kstate_stream *stream, int id)
{
	struct kstate_entry *ke = stream->pos;

	while (ke->section_type == KS_SUBSECTION) {
		if (ke->state_id == id)
			return ke;

		ke = (struct kstate_entry *)(ke->data + ke->size);
	}
	return NULL;
}

static void subsection_load(struct kstate_stream *stream, int id,
			struct kstate_description *ksd, void *obj)
{
	struct kstate_entry *start_ke, *ke;
	const struct kstate_description *const *section;

	if (!ksd->subsections)
		return;

	start_ke = stream->pos;
	section = ksd->subsections;
	while (*section) {
		stream->pos = start_ke;
		ke = find_subsection(stream, (*section)->id);
		if (ke) {
			stream->pos = ke;
			restore_kstate(stream, id, *section, obj);
		}
		section++;
	}
}

int kstate_restore(struct kstate_description *state, void *obj, int id)
{
	struct kstate_stream stream;
	struct kstate_entry *ke;

	if (kstate_stream_addr == NULL)
		return -ENOENT;

	if (*(u32 *)kstate_stream_addr != KSTATE_MAGIC) {
		kstate_stream_addr = NULL;
		return -ENOENT;
	}

	ke = (struct kstate_entry *)(kstate_stream_addr + sizeof(u32));
	if (WARN_ON_ONCE(ke->state_id == 0))
		return -ENOENT;

	stream.pos = ke;
	while (ke->section_type != KS_EOF) {
		if (ke->state_id != state->id ||
		    ke->instance_id != id) {
			ke = (struct kstate_entry *)(ke->data + ke->size);
			continue;
		}
		stream.pos = ke;
		restore_kstate(&stream, id, state, obj);
		ke = (struct kstate_entry *)(ke->data + ke->size);
		subsection_load(&stream, id, state, obj);
		return 0;
	}
	return -ENOENT;
}

int kstate_register(struct kstate_description *state, void *obj, int id)
{
	struct state_entry *se;

	se = kmalloc(sizeof(*se), GFP_KERNEL);
	if (!se)
		return -ENOMEM;

	se->kstd = state;
	se->id = id;
	se->obj = obj;

	mutex_lock(&states_lock);
	list_add(&se->list, &states);
	mutex_unlock(&states_lock);
	return 0;
}

void kstate_unregister(struct kstate_description *state, void *obj, int id)
{
	struct state_entry *se, *tmp;

	mutex_lock(&states_lock);
	list_for_each_entry_safe(se, tmp, &states, list) {
		if (se->id == id && se->obj == obj) {
			list_del(&se->list);
			break;
		}
	}
	mutex_unlock(&states_lock);
	kfree(se);
}

int kstate_register_restore(struct kstate_description *state, void *obj)
{
	int id = atomic_inc_return(&state->instance_id);

	kstate_register(state, obj, id);
	return kstate_restore(state, obj, id);
}

int kstate_folio_restore(struct kstate_stream *stream, void *obj,
			const struct kstate_field *field)
{
	phys_addr_t paddr;
	struct folio *folio;

	kstate_restore_data(stream, &paddr, sizeof(paddr));
	folio = kho_restore_folio(paddr);
	if (!folio)
		return -ENOENT;

	*(struct folio **)obj = folio;
	return 0;
}

int kstate_folio_save(struct kstate_stream *stream, void *obj,
		const struct kstate_field *field)
{
	struct folio *folio = *(struct folio **)obj;
	phys_addr_t paddr = PFN_PHYS(folio_pfn(folio));
	int ret;

	ret = kstate_save_data(stream, &paddr, sizeof(paddr));
	if (ret)
		return ret;

	return kho_preserve_folio(folio);
}


struct kstate_out {
	union {
		phys_addr_t kstate_paddr;
		u8 data[PAGE_SIZE];
	};
};

int kstate_abort(void)
{
	free_kstate_stream();
	return 0;
}

int kstate_finalize(void)
{
	int err = 0;
	struct kstate_out *kstate_out = phys_to_virt(kstate_out_paddr);
	struct folio *kstate_out_folio = page_folio(phys_to_page(kstate_out_paddr));

	err = kstate_save_state();
	if (err)
		return err;

	err = kho_preserve_folio(kstate_out_folio);
	if (err)
		goto out_save_state;

	err = kho_preserve_folio(kstate_stream.folio);
	if (err)
		goto out;

	kstate_out->kstate_paddr = PFN_PHYS(folio_pfn(kstate_stream.folio));
out:
	if (err)
		kho_unpreserve_folio(kstate_out_folio);
out_save_state:
	if (err)
		free_kstate_stream();

	return err;
}

static int __init kstate_init(void)
{
	struct page *page;
	int err;

	if (!kho_is_enabled())
		return 0;

	page = alloc_page(GFP_KERNEL | __GFP_ZERO);
	if (!page)
		return -ENOMEM;

	kstate_out_paddr = page_to_phys(page);
	return err;
}
late_initcall(kstate_init);

int __init kstate_early_init(phys_addr_t kstate_entries, u64 len)
{
	struct kstate_out *kstate_out;

	kstate_out = early_memremap(kstate_entries, len);
	if (!kstate_out) {
		pr_err("%s failed\n", __func__);
		return -ENOMEM;
	}
	kstate_stream_addr = phys_to_virt(kstate_out->kstate_paddr);
	early_memunmap(kstate_out, len);
	return 0;
}
