KSTATE: Kernel state preservation framework
===========================================

KSTATE (kernel state) is framework to migrate some part of the internal
kernel state (device driver, memory, etc) from one kernel to another accross
kexec reboot.

The purpose is being able to update host kernel under VMs with VFIO
pass-through devices running on that host.

kstate_description
------------------

Most kernel's state is in structs and structs could be described by
kstate_description

struct kstate_test_data {
	int i;
	unsigned long *p_ulong;
	char s[10];
	struct page *page;
};

struct kstate_description test_state_v2 = {
	.name = "test_v2",
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
		KSTATE_PAGE(page, struct kstate_test_data),
		KSTATE_BASE_TYPE_DEPRECATED(k, struct kstate_test_data, u16, 1),
		KSTATE_END_OF_LIST()
	},
	.subsections = (const struct kstate_description *[]){
		&test_state_v2,
		NULL
	},
};

Changing data structures
------------------------

KSTATE saves/restores structs as a series of fields. When the kernel structs
are changed we may need to change the state to store more/different information.

Versions
--------

Version numbers are intended for major incompatible changes, that are not
backward compatible.

Each version is associated with a series of fields saved. The state is always
saved as the newest version specified by ->version_id.
But loading state sometimes is able to load state from an older version.

There are two version fields:

    - version_id: the maximum version_id supported by kstate_description.
    - min_version_id: the minimum version_id that given kstate_description is able to understand.

KSTATE is able to read versions from minimum_version_id to version_id.

There are _V forms of many KSTATE_ macros to load fields for version dependent fields, e.g.

	KSTATE_BASE_TYPE_V(i, struct kstate_test_data, int, 2),

only loads that field for versions 2 and newer.

Saving state will always create a section with the ‘version_id’ value and thus can’t
be loaded by any older kernel.

Removing field
--------------
If field is no longer needed it could be marked deprecated using
KSTATE_*_DEPRECATED macro and bumping ->version_id of kstate_description.
The last parameter of the macro is the last version number that have this field.
Old kernel will save such field, but new kernel will skip it on load. Also
the new kernel will not save such field (as there is nothing to save).
Such change is not backward compatible.

Adding new field
----------------

Addition of new field can be done as version dependant field by using _V form of
KSTATE_ macro:
	KSTATE_BASE_TYPE_V(i, struct kstate_test_data, int, 2),
This is not backward compatible.

Another option is adding subsection to kstate_description. A subsection is
additional kstate_description which linked to the main one. Subsection must
have a unique ->id. If the receiving side finds a subsection with unknown id
that it will be ignored. This make subsections suitable for backward compatible
changes (migrate from N+1 to N kernel)
