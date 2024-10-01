// SPDX-License-Identifier: GPL-2.0
#include <linux/io.h>
#include <linux/kstate.h>
#include <linux/mm.h>
#include <linux/module.h>

static unsigned long ulong_val;
struct kstate_test_data {
	int i;
	unsigned long *p_ulong;
	char s[10];
	struct page *page;
};

struct kstate_description test_state = {
	.name = "test",
	.version_id = 1,
	.id = KSTATE_TEST_ID,
	.state_list = LIST_HEAD_INIT(test_state.state_list),
	.fields = (const struct kstate_field[]) {
		KSTATE_BASE_TYPE(i, struct kstate_test_data, int),
		KSTATE_BASE_TYPE(s, struct kstate_test_data, char [10]),
		KSTATE_POINTER(p_ulong, struct kstate_test_data),
		KSTATE_PAGE(page, struct kstate_test_data),
		KSTATE_END_OF_LIST()
	},
};

static struct kstate_test_data test_data;

static int init_test_data(void)
{
	struct page *page;
	int i;

	test_data.i = 10;
	ulong_val = 20;
	memcpy(test_data.s, "abcdefghk", sizeof(test_data.s));
	page = alloc_page(GFP_KERNEL);
	if (!page)
		return -ENOMEM;

	for (i = 0; i < PAGE_SIZE/4; i += 4)
		*((u32 *)page_address(page) + i) = 0xdeadbeef;
	test_data.page = page;
	return 0;
}

static void validate_test_data(void)
{
	int i;

	if (WARN_ON(test_data.i != 10))
		return;
	if (WARN_ON(*test_data.p_ulong != 20))
		return;
	if (WARN_ON(strcmp(test_data.s, "abcdefghk") != 0))
		return;

	for (i = 0; i < PAGE_SIZE/4; i += 4) {
		u32 val = *((u32 *)page_address(test_data.page) + i);

		WARN_ON(val != 0xdeadbeef);
	}
}

static int __init test_kstate_init(void)
{
	int ret = 0;

	test_data.p_ulong = &ulong_val;

	if (!is_kstate_kernel()) {
		ret = init_test_data();
		if (ret)
			goto out;
	}

	kstate_register(&test_state, &test_data);

	validate_test_data();

out:
	return ret;
}
__initcall(test_kstate_init);
