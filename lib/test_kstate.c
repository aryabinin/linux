// SPDX-License-Identifier: GPL-2.0
#define pr_fmt(fmt) "kstate test: " fmt
#include <linux/io.h>
#include <linux/kexec_handover.h>
#include <linux/kstate.h>
#include <linux/mm.h>
#include <linux/module.h>

static unsigned long ulong_val;
struct kstate_test_data {
	int i;
	unsigned long *p_ulong;
	char s[10];
	struct folio *folio;
};

#define KSTATE_TEST_DATA_ID 123

struct kstate_description test_state_v2 = {
	.name = "test_v2",
	.version_id = 1,
	.id = KSTATE_TEST_ID_V2,
	.fields = (const struct kstate_field[]) {
		KSTATE_BASE_TYPE(i, struct kstate_test_data, int),
		KSTATE_END_OF_LIST()
	},
};

struct kstate_description test_state = {
	.name = "test",
	.version_id = 2,
	.id = KSTATE_TEST_ID,
	.fields = (const struct kstate_field[]) {
		KSTATE_BASE_TYPE(s, struct kstate_test_data, char [10]),
		KSTATE_POINTER(p_ulong, struct kstate_test_data),
		KSTATE_FOLIO(folio, struct kstate_test_data),
		KSTATE_BASE_TYPE_DEPRECATED(k, u16, 1),
		KSTATE_END_OF_LIST()
	},
	.subsections = (const struct kstate_description *[]){
		&test_state_v2,
		NULL
	},
};

static struct kstate_test_data test_data;

static int init_test_data(void)
{
	struct folio *folio;
	int i;

	test_data.i = 10;
	ulong_val = 20;
	memcpy(test_data.s, "abcdefghk", sizeof(test_data.s));
	folio = folio_alloc(GFP_KERNEL, 0);
	if (!folio)
		return -ENOMEM;

	for (i = 0; i < folio_size(folio)/sizeof(u32); i += 4)
		*((u32 *)folio_address(folio) + i) = 0xdeadbeef;
	test_data.folio = folio;
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

	for (i = 0; i < folio_size(test_data.folio)/4; i += 4) {
		u32 val = *((u32 *)folio_address(test_data.folio) + i);

		if (WARN_ON_ONCE(val != 0xdeadbeef))
			return;
	}
}

static int __init test_kstate_init(void)
{
	int ret = 0;

	test_data.p_ulong = &ulong_val;

	ret = kstate_register(&test_state, &test_data, KSTATE_TEST_DATA_ID);
	if (ret) {
		pr_err("register failed %d\n", ret);
		goto out;
	}

	if (!is_kho_boot()) {
		ret = init_test_data();
		if (ret)
			goto out;
	} else {
		pr_info("restoring data\n");
		ret = kstate_restore(&test_state, &test_data, KSTATE_TEST_DATA_ID);
		if (ret) {
			pr_err("restore failed %d\n", ret);
			goto out;
		}

	}

	validate_test_data();

out:
	return ret;
}
late_initcall(test_kstate_init);
