#include <linux/bug.h>
#include <linux/ctype.h>
#include <linux/types.h>
#include <linux/sched.h>

#include "ubsan.h"

const char *type_check_kinds[] = {
	"load of",
	"store to",
	"reference binding to",
	"member access within",
	"member call on",
	"constructor call on",
	"downcast of",
	"downcast of"
};

enum {
	SUM_OVERFLOW,
	SUB_OVERFLOW,
	MUL_OVERFLOW,
	NEG_OVERFLOW,
	DIVREM_OVERFLOW,
	TYPE_MISMATCH,
	NONNULL_ARG,
	NONNULL_RET,
	VLA_BOUND,
	OUT_OF_BOUNDS,
	SHIFT_OUT_OF_BOUNDS,
	INVALID_LOAD,
	FUNC_TYPE_MISMATCH,
	HANDLERS_END,
};

/* By default enable everything except type mismatch handler */
static unsigned long ubsan_handle = GEN_MASK(HANDLERS_END, 0) & ~BIT_MASK(TYPE_MISMATCH);

static void enable_handler(unsigned int handler)
{
	set_bit(handler, &ubsan_handle);
}

static void disable_handler(unsigned int handler)
{
	clear_bit(handler, &ubsan_handle);
}

static bool handler_enabled(unsigned int handler)
{
	return test_bit(handler, &ubsan_handle);
}

#define REPORTED_BIT 31
#define COLUMN_MASK (~(1U << REPORTED_BIT))

static bool is_disabled(struct source_location *location)
{
	return test_and_set_bit(REPORTED_BIT,
				(unsigned long *)&location->column);
}

static void print_source_location(const char *prefix, struct source_location *loc)
{
	pr_err("%s %s:%d:%d\n", prefix, loc->file_name,
		loc->line, loc->column & COLUMN_MASK);
}

static bool type_is_int(struct type_descriptor *type)
{
	return type->type_kind == type_kind_int;
}

static bool type_is_signed(struct type_descriptor *type)
{
	return type_is_int(type) && (type->type_info & 1);
}

static unsigned type_bit_width(struct type_descriptor *type)
{
	return 1 << (type->type_info >> 1);
}

static bool is_inline_int(struct type_descriptor *type)
{
	unsigned inline_bits = sizeof(unsigned long)*8;
	unsigned bits = type_bit_width(type);

	return bits <= inline_bits;
}

static s_max get_signed_val(struct type_descriptor *type, unsigned long val)
{
	if (is_inline_int(type)) {
		unsigned extra_bits = sizeof(s_max)*8 - type_bit_width(type);
		return ((s_max)val) << extra_bits >> extra_bits;
	}

	if (type_bit_width(type) == 64)
		return *(s64 *)val;

	return *(s_max *)val;
}

static bool val_is_negative(struct type_descriptor *type, unsigned long val)
{
	return type_is_signed(type) && get_signed_val(type, val) < 0;
}

static u_max get_unsigned_val(struct type_descriptor *type, unsigned long val)
{
	if (is_inline_int(type))
		return val;

	if (type_bit_width(type) == 64)
		return *(u64 *)val;

	return *(u_max *)val;
}

static void val_to_string(char *str, size_t size, struct type_descriptor *type,
	unsigned long value)
{
	u_max val = get_unsigned_val(type, value);

	if (type_is_int(type)) {
		if (type_bit_width(type) == 128)
			scnprintf(str, size, "0x%08x%08x%08x%08x",
				(u32)(val >> 96),
				(u32)(val >> 64),
				(u32)(val >> 32),
				(u32)(val));
		else if (type_is_signed(type))
			scnprintf(str, size, "%lld",
				(s64)get_signed_val(type, value));
		else
			scnprintf(str, size, "%llu",
				(u64)get_unsigned_val(type, value));
	}
}

static bool location_is_valid(struct source_location *loc)
{
	return loc->file_name != NULL;
}

static void ubsan_prologue(struct source_location *location)
{
	current->in_ubsan++;
	pr_err("========================================"
		"========================================\n");
	print_source_location("UBSan: Undefined behaviour in", location);
}

static void ubsan_epilogue(void)
{
	dump_stack();
	pr_err("========================================"
		"========================================\n");
	current->in_ubsan--;
}

static void handle_overflow(struct overflow_data *data, unsigned long lhs,
			unsigned long rhs, char op)
{

	struct type_descriptor *type = data->type;
	char lhs_val_str[60];
	char rhs_val_str[60];

	if (current->in_ubsan)
		return;

	if (is_disabled(&data->location))
		return;

	ubsan_prologue(&data->location);

	val_to_string(lhs_val_str, sizeof(lhs_val_str), type, lhs);
	val_to_string(rhs_val_str, sizeof(rhs_val_str), type, rhs);
	pr_err("%s integer overflow:\n",
		type_is_signed(type) ? "signed" : "unsigned");
	pr_err("%s %c %s cannot be represented in type %s\n",
		lhs_val_str,
		op,
		rhs_val_str,
		type->type_name);

	ubsan_epilogue();
}

void __ubsan_handle_add_overflow(struct overflow_data *data,
				unsigned long lhs,
				unsigned long rhs)
{

	if (handler_enabled(SUM_OVERFLOW))
		handle_overflow(data, lhs, rhs, '+');
}
EXPORT_SYMBOL(__ubsan_handle_add_overflow);

void __ubsan_handle_sub_overflow(struct overflow_data *data,
				unsigned long lhs,
				unsigned long rhs)
{
	if (handler_enabled(SUB_OVERFLOW))
		handle_overflow(data, lhs, rhs, '-');
}
EXPORT_SYMBOL(__ubsan_handle_sub_overflow);

void __ubsan_handle_mul_overflow(struct overflow_data *data,
				unsigned long lhs,
				unsigned long rhs)
{
	if (handler_enabled(MUL_OVERFLOW))
		handle_overflow(data, lhs, rhs, '*');
}
EXPORT_SYMBOL(__ubsan_handle_mul_overflow);

void __ubsan_handle_negate_overflow(struct overflow_data *data,
				unsigned long old_val)
{

	char old_val_str[60];

	if (!handler_enabled(NEG_OVERFLOW))
		return;

	if (current->in_ubsan)
		return;

	if (is_disabled(&data->location))
		return;

	ubsan_prologue(&data->location);

	val_to_string(old_val_str, sizeof(old_val_str), data->type, old_val);

	if (type_is_signed(data->type))
		pr_err("negation of %s cannot be represented in type %s:"
			"cast to an unsigned type to negate this value to itself\n",
			old_val_str, data->type->type_name);
	else
		pr_err("negation of %s cannot be represented in type %s\n",
			old_val_str, data->type->type_name);

	ubsan_epilogue();
}
EXPORT_SYMBOL(__ubsan_handle_negate_overflow);


void __ubsan_handle_divrem_overflow(struct overflow_data *data,
				unsigned long lhs,
				unsigned long rhs)
{
	char rhs_val_str[60];

	if (!handler_enabled(DIVREM_OVERFLOW))
		return;

	if (current->in_ubsan)
		return;

	if (is_disabled(&data->location))
		return;

	ubsan_prologue(&data->location);

	val_to_string(rhs_val_str, sizeof(rhs_val_str), data->type, rhs);

	if (type_is_signed(data->type) && get_signed_val(data->type, rhs) == -1)
		pr_err("division of %s by -1 cannot be represented in type %s\n",
			rhs_val_str, data->type->type_name);
	else
		pr_err("division by zero\n");

	ubsan_epilogue();
}
EXPORT_SYMBOL(__ubsan_handle_divrem_overflow);

void __ubsan_handle_type_mismatch(struct type_mismatch_data *data,
				unsigned long ptr)
{

	if (!handler_enabled(TYPE_MISMATCH))
		return;

	if (current->in_ubsan)
		return;

	if (is_disabled(&data->location))
		return;

	ubsan_prologue(&data->location);

	if (!ptr) {
		pr_err("%s null pointer of type %s\n",
			type_check_kinds[data->type_check_kind],
			data->type->type_name);
	} else if (data->aligment && (ptr & (data->aligment - 1))) {
		pr_err("%s misaligned address %p for type %s which requires %ld byte alignment\n",
			type_check_kinds[data->type_check_kind],
			(void *)ptr, data->type->type_name, data->aligment);
	} else {
		pr_err("%s address %pk with insufficient space\n",
			type_check_kinds[data->type_check_kind],
			(void *) ptr);
		pr_err("for an object of type %s\n", data->type->type_name);
	}

	ubsan_epilogue();
}
EXPORT_SYMBOL(__ubsan_handle_type_mismatch);

void __ubsan_handle_nonnull_arg(struct nonnull_arg_data *data)
{

	if (!handler_enabled(NONNULL_ARG))
		return;

	if (current->in_ubsan)
		return;

	if (is_disabled(&data->location))
		return;

	ubsan_prologue(&data->location);

	pr_err("null pointer passed as argument %d, declared with nonnull attribute\n",
		data->arg_index);

	if (location_is_valid(&data->attr_location))
		print_source_location("nonnull attribute declared in ",
				&data->attr_location);

	ubsan_epilogue();
}
EXPORT_SYMBOL(__ubsan_handle_nonnull_arg);

void __ubsan_handle_nonnull_return(struct nonnull_return_data *data)
{
	if (!handler_enabled(NONNULL_RET))
		return;

	if (current->in_ubsan)
		return;

	if (is_disabled(&data->location))
		return;

	ubsan_prologue(&data->location);

	pr_err("null pointer returned from function declared to never return null\n");

	if (location_is_valid(&data->attr_location))
		print_source_location("returns_nonnull attribute specified in",
				&data->attr_location);

	ubsan_epilogue();
}
EXPORT_SYMBOL(__ubsan_handle_nonnull_return);

void __ubsan_handle_vla_bound_not_positive(struct vla_bound_data *data,
					unsigned long bound)
{
	char bound_str[60];

	if (!handler_enabled(VLA_BOUND))
		return;

	if (current->in_ubsan)
		return;

	if (is_disabled(&data->location))
		return;

	ubsan_prologue(&data->location);

	print_source_location("UBSan: Undefined behaviour in", &data->location);

	val_to_string(bound_str, sizeof(bound_str), data->type, bound);
	pr_err("variable length array bound value %s <= 0\n", bound_str);

	ubsan_epilogue();
}
EXPORT_SYMBOL(__ubsan_handle_vla_bound_not_positive);

void __ubsan_handle_out_of_bounds(struct out_of_bounds_data *data,
				unsigned long index)
{
	char index_str[60];

	if (!handler_enabled(OUT_OF_BOUNDS))
		return;

	if (current->in_ubsan)
		return;

	if (is_disabled(&data->location))
		return;

	ubsan_prologue(&data->location);

	val_to_string(index_str, sizeof(index_str), data->index_type, index);
	pr_err("index %s out of bounds for type %s\n", index_str,
		data->array_type->type_name);

	ubsan_epilogue();
}
EXPORT_SYMBOL(__ubsan_handle_out_of_bounds);

void __ubsan_handle_shift_out_of_bounds(
	struct shift_out_of_bounds_data *data,
	unsigned long lhs,
	unsigned long rhs)
{
	struct type_descriptor *rhs_type = data->rhs_type;
	struct type_descriptor *lhs_type = data->lhs_type;
	char rhs_str[60];
	char lhs_str[60];

	if (!handler_enabled(SHIFT_OUT_OF_BOUNDS))
		return;

	if (current->in_ubsan)
		return;

	if (is_disabled(&data->location))
		return;

	ubsan_prologue(&data->location);

	val_to_string(rhs_str, sizeof(rhs_str), rhs_type, rhs);
	val_to_string(lhs_str, sizeof(lhs_str), lhs_type, lhs);

	if (val_is_negative(rhs_type, rhs))
		pr_err("shift exponent %s is negative\n", rhs_str);

	else if (get_unsigned_val(rhs_type, rhs) >=
		type_bit_width(lhs_type))
		pr_err("shift exponent %s is to large for %u-bit type %s\n",
			rhs_str,
			type_bit_width(lhs_type),
			lhs_type->type_name);
	else if (val_is_negative(lhs_type, lhs))
		pr_err("left shift of negative value %s\n",
			lhs_str);
	else
		pr_err("left shift of %s by %s places cannot be"
			"represented in type %s\n",
			lhs_str, rhs_str,
			lhs_type->type_name);

	ubsan_epilogue();
}
EXPORT_SYMBOL(__ubsan_handle_shift_out_of_bounds);

void __ubsan_handle_load_invalid_value(struct invalid_value_data *data,
				unsigned long val)
{
	char val_str[60];

	if (!handler_enabled(INVALID_LOAD))
		return;

	if (current->in_ubsan)
		return;

	if (is_disabled(&data->location))
		return;

	ubsan_prologue(&data->location);

	val_to_string(val_str, sizeof(val_str), data->type, val);

	pr_err("load of value %s is not a valid value for type %s\n",
		val_str, data->type->type_name);

	ubsan_epilogue();
}
EXPORT_SYMBOL(__ubsan_handle_load_invalid_value);


void __ubsan_handle_function_type_mismatch(struct func_type_mismatch_data *data,
					unsigned long function)
{

	if (!handler_enabled(FUNC_TYPE_MISMATCH))
		return;

	if (current->in_ubsan)
		return;

	if (is_disabled(&data->location))
		return;

	ubsan_prologue(&data->location);

	pr_err("call to function %pF through pointer to incorrect function type %s\n",
		(void *)function, data->type->type_name);

	ubsan_epilogue();
}
EXPORT_SYMBOL(__ubsan_handle_function_type_mismatch);

static int __init enable_ubsan_handlers(char *str)
{
	for (; *str; str++) {
		switch (tolower(*str)) {
		case 'o':
			enable_handler(SUM_OVERFLOW);
			enable_handler(SUB_OVERFLOW);
			enable_handler(MUL_OVERFLOW);
			enable_handler(NEG_OVERFLOW);
			enable_handler(DIVREM_OVERFLOW);
			break;
		case 't':
			enable_handler(TYPE_MISMATCH);
			break;
		case 'n':
			enable_handler(NONNULL_ARG);
			enable_handler(NONNULL_RET);
			break;
		case 'v':
			enable_handler(VLA_BOUND);
			break;
		case 'b':
			enable_handler(OUT_OF_BOUNDS);
			break;
		case 's':
			enable_handler(SHIFT_OUT_OF_BOUNDS);
			break;
		case 'i':
			enable_handler(INVALID_LOAD);
			break;
		case 'f':
			enable_handler(FUNC_TYPE_MISMATCH);
			break;
		default:
			pr_err("skipping unknown option '%c'\n", *str);
			break;
		}
	}

	return 0;
}

static int __init disable_ubsan_handlers(char *str)
{
	for (; *str; str++) {
		switch (tolower(*str)) {
		case 'o':
			disable_handler(SUM_OVERFLOW);
			disable_handler(SUB_OVERFLOW);
			disable_handler(MUL_OVERFLOW);
			disable_handler(NEG_OVERFLOW);
			disable_handler(DIVREM_OVERFLOW);
			break;
		case 't':
			disable_handler(TYPE_MISMATCH);
			break;
		case 'n':
			disable_handler(NONNULL_ARG);
			disable_handler(NONNULL_RET);
			break;
		case 'v':
			disable_handler(VLA_BOUND);
			break;
		case 'b':
			disable_handler(OUT_OF_BOUNDS);
			break;
		case 's':
			disable_handler(SHIFT_OUT_OF_BOUNDS);
			break;
		case 'i':
			disable_handler(INVALID_LOAD);
			break;
		case 'f':
			disable_handler(FUNC_TYPE_MISMATCH);
			break;
		default:
			pr_err("skipping unknown option '%c'\n", *str);
			break;
		}
	}

	return 0;
}

early_param("ubsan_disable", disable_ubsan_handlers);
early_param("ubsan_enable", enable_ubsan_handlers);
