/*
 * (C) 2021-2022 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
 * All Rights Reserved.
 *
 * Author: Neels Janosch Hofmeyr <nhofmeyr@sysmocom.de>
 *
 * SPDX-License-Identifier: GPL-2.0+
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <stdio.h>
#include <errno.h>
#include <assert.h>

#include <osmocom/core/application.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/msgb.h>

#include <osmocom/gtlv/gtlv_dec_enc.h>

void *ctx;

enum tags {
	TAG_FOO = 1,
	TAG_BAR,
	TAG_BAZ,
	TAG_REPEAT_INT,
	TAG_REPEAT_STRUCT,
	TAG_NEST,
};

const struct value_string tag_names[] = {
	{ TAG_FOO, "FOO" },
	{ TAG_BAR, "BAR" },
	{ TAG_BAZ, "BAZ" },
	{ TAG_REPEAT_INT, "REPEAT_INT" },
	{ TAG_REPEAT_STRUCT, "REPEAT_STRUCT" },
	{ TAG_NEST, "NEST" },
	{}
};

struct bar {
	char str[23];
};

struct baz {
	int v_int;
	bool v_bool;
};

enum repeat_enum {
	R_A,
	R_B,
	R_C,
};

const struct value_string repeat_enum_names[] = {
	OSMO_VALUE_STRING(R_A),
	OSMO_VALUE_STRING(R_B),
	OSMO_VALUE_STRING(R_C),
	{}
};

struct repeat {
	int v_int;
	bool v_bool;
	enum repeat_enum v_enum;
};

struct nested_inner_msg {
	int foo;
	struct bar bar;
	struct baz baz;
};

struct decoded_msg {
	int foo;
	struct bar bar;

	bool baz_present;
	struct baz baz;

	unsigned int repeat_int_count;
	int repeat_int[32];

	unsigned int repeat_struct_count;
	struct repeat repeat_struct[32];

	bool nest_present;
	struct nested_inner_msg nest;
};

int dec_u16(void *decoded_struct, void *decode_to, const struct osmo_gtlv_load *gtlv)
{
	int *foo = decode_to;
	if (gtlv->len != 2)
		return -EINVAL;
	*foo = osmo_load16be(gtlv->val);
	return 0;
}

int enc_u16(struct osmo_gtlv_put *gtlv, const void *decoded_struct, const void *encode_from)
{
	const int *foo = encode_from;
	if (*foo > INT16_MAX)
		return -EINVAL;
	msgb_put_u16(gtlv->dst, *foo);
	return 0;
}

int enc_to_str_u16(char *buf, size_t buflen, const void *encode_from)
{
	const int *foo = encode_from;
	return snprintf(buf, buflen, "%d", *foo);
}

int dec_bar(void *decoded_struct, void *decode_to, const struct osmo_gtlv_load *gtlv)
{
	struct bar *bar = decode_to;
	if (gtlv->len > sizeof(bar->str) - 1)
		return -EINVAL;
	osmo_strlcpy(bar->str, (const char *)gtlv->val, OSMO_MIN(gtlv->len + 1, sizeof(bar->str)));
	return 0;
}

int enc_bar(struct osmo_gtlv_put *gtlv, const void *decoded_struct, const void *encode_from)
{
	const struct bar *bar = encode_from;
	int len = strnlen(bar->str, sizeof(bar->str));
	memcpy(msgb_put(gtlv->dst, len), bar, len);
	return 0;
}

int enc_to_str_bar(char *buf, size_t buflen, const void *encode_from)
{
	const struct bar *bar = encode_from;
	return osmo_quote_str_buf3(buf, buflen, bar->str, -1);
}

int dec_baz(void *decoded_struct, void *decode_to, const struct osmo_gtlv_load *gtlv)
{
	struct baz *baz = decode_to;
	uint16_t l;
	if (gtlv->len != 2)
		return -EINVAL;
	l = osmo_load16be(gtlv->val);
	baz->v_int = l & 0x7fff;
	baz->v_bool = (l & 0x8000) ? true : false;
	return 0;
}

int enc_baz(struct osmo_gtlv_put *gtlv, const void *decoded_struct, const void *encode_from)
{
	const struct baz *baz = encode_from;
	if (baz->v_int > 0x7fff)
		return -EINVAL;
	msgb_put_u16(gtlv->dst, (baz->v_bool ? 0x8000 : 0) + (baz->v_int & 0x7fff));
	return 0;
}

int enc_to_str_baz(char *buf, size_t buflen, const void *encode_from)
{
	const struct baz *baz = encode_from;
	return snprintf(buf, buflen, "{%d,%s}", baz->v_int, baz->v_bool ? "true" : "false");
}

int dec_repeat_struct(void *decoded_struct, void *decode_to, const struct osmo_gtlv_load *gtlv)
{
	struct repeat *repeat_struct = decode_to;
	if (gtlv->len != 3)
		return -EINVAL;
	repeat_struct->v_int = osmo_load16be(gtlv->val);
	repeat_struct->v_bool = gtlv->val[2] & 0x80;
	repeat_struct->v_enum = gtlv->val[2] & 0x7f;
	return 0;
}

int enc_repeat_struct(struct osmo_gtlv_put *gtlv, const void *decoded_struct, const void *encode_from)
{
	const struct repeat *repeat_struct = encode_from;
	msgb_put_u16(gtlv->dst, repeat_struct->v_int);
	msgb_put_u8(gtlv->dst, (repeat_struct->v_bool ? 0x80 : 0) + (repeat_struct->v_enum & 0x7f));
	return 0;
}

int enc_to_str_repeat_struct(char *buf, size_t buflen, const void *encode_from)
{
	const struct repeat *repeat_struct = encode_from;
	return snprintf(buf, buflen, "{%d,%s,%s}", repeat_struct->v_int, repeat_struct->v_bool ? "true" : "false",
			get_value_string(repeat_enum_names, repeat_struct->v_enum));
}

struct osmo_gtlv_coding nested_inner_msg_ies[] = {
	{
		.ti = { TAG_FOO },
		.dec_func = dec_u16,
		.enc_func = enc_u16,
		.enc_to_str_func = enc_to_str_u16,
		.memb_ofs = offsetof(struct nested_inner_msg, foo),
	},
	{
		.ti = { TAG_BAR },
		.dec_func = dec_bar,
		.enc_func = enc_bar,
		.enc_to_str_func = enc_to_str_bar,
		.memb_ofs = offsetof(struct nested_inner_msg, bar),
	},
	{
		.ti = { TAG_BAZ },
		.dec_func = dec_baz,
		.enc_func = enc_baz,
		.enc_to_str_func = enc_to_str_baz,
		.memb_ofs = offsetof(struct nested_inner_msg, baz),
	},
	{}
};

struct osmo_gtlv_coding msg_ie_coding[] = {
	{
		.ti = { TAG_FOO },
		.dec_func = dec_u16,
		.enc_func = enc_u16,
		.enc_to_str_func = enc_to_str_u16,
		.memb_ofs = offsetof(struct decoded_msg, foo),
	},
	{
		.ti = { TAG_BAR },
		.dec_func = dec_bar,
		.enc_func = enc_bar,
		.enc_to_str_func = enc_to_str_bar,
		.memb_ofs = offsetof(struct decoded_msg, bar),
	},
	{
		.ti = { TAG_BAZ },
		.dec_func = dec_baz,
		.enc_func = enc_baz,
		.enc_to_str_func = enc_to_str_baz,
		.memb_ofs = offsetof(struct decoded_msg, baz),
		.has_presence_flag = true,
		.presence_flag_ofs = offsetof(struct decoded_msg, baz_present),
	},
	{
		.ti = { TAG_REPEAT_INT },
		.dec_func = dec_u16,
		.enc_func = enc_u16,
		.enc_to_str_func = enc_to_str_u16,
		.memb_ofs = offsetof(struct decoded_msg, repeat_int),
		.memb_array_pitch = OSMO_MEMB_ARRAY_PITCH(struct decoded_msg, repeat_int),
		.has_count = true,
		.count_ofs = offsetof(struct decoded_msg, repeat_int_count),
		.count_max = ARRAY_SIZE(((struct decoded_msg *)0)->repeat_int),
	},
	{
		.ti = { TAG_REPEAT_STRUCT },
		.dec_func = dec_repeat_struct,
		.enc_func = enc_repeat_struct,
		.enc_to_str_func = enc_to_str_repeat_struct,
		.memb_ofs = offsetof(struct decoded_msg, repeat_struct),
		.memb_array_pitch = OSMO_MEMB_ARRAY_PITCH(struct decoded_msg, repeat_struct),
		.has_count = true,
		.count_ofs = offsetof(struct decoded_msg, repeat_struct_count),
		.count_max = ARRAY_SIZE(((struct decoded_msg *)0)->repeat_struct),
	},
	{
		.ti = { TAG_NEST },
		.memb_ofs = offsetof(struct decoded_msg, nest),
		.nested_ies = nested_inner_msg_ies,
		.has_presence_flag = true,
		.presence_flag_ofs = offsetof(struct decoded_msg, nest_present),
	},
	{}
};

char *decoded_msg_to_str(const struct decoded_msg *m)
{
	return osmo_gtlvs_encode_to_str_c(ctx, m, 0, msg_ie_coding, tag_names);
}


const struct decoded_msg enc_dec_tests[] = {
	{
		.foo = 23,
		.bar = { "twentythree" },
	},
	{
		.foo = 23,
		.bar = { "twentythree" },

		.baz_present = true,
		.baz = {
			.v_int = 2323,
			.v_bool = true,
		},
	},
	{
		.foo = 23,
		.bar = { "twentythree" },

		.baz_present = true,
		.baz = {
			.v_int = 2323,
			.v_bool = true,
		},

		.repeat_int_count = 3,
		.repeat_int = { 1, 2, 0x7fff },
	},
	{
		.foo = 23,
		.bar = { "twentythree" },

		.baz_present = true,
		.baz = {
			.v_int = 2323,
			.v_bool = true,
		},

		.repeat_int_count = 3,
		.repeat_int = { 1, 2, 0x7fff },

		.repeat_struct_count = 2,
		.repeat_struct = {
			{
				.v_int = 1001,
				.v_bool = true,
				.v_enum = R_A,
			},
			{
				.v_int = 1002,
				.v_bool = false,
				.v_enum = R_B,
			},
		},

		.nest_present = true,
		.nest = {
			.foo = 42,
			.bar = { "fortytwo" },
			.baz = {
				.v_int = 4242,
				.v_bool = false,
			},
		},
	},
};

static int verify_err_cb_data;

void err_cb(void *data, void *decoded_struct, const char *file, int line, const char *fmt, ...)
{
	assert(data == &verify_err_cb_data);
	va_list args;
	va_start(args, fmt);
	//printf("ERR: %s:%d ", file, line);
	printf("ERR: ");
	vprintf(fmt, args);
	va_end(args);
}

void test_enc_dec(const char *label, const struct osmo_gtlv_cfg *cfg, bool ordered)
{
	int i;
	for (i = 0; i < ARRAY_SIZE(enc_dec_tests); i++) {
		int rc;
		const struct decoded_msg *orig = &enc_dec_tests[i];
		struct decoded_msg parsed = {};
		struct osmo_gtlv_load load;
		struct osmo_gtlv_put put;

		printf("\n=== start %s %s[%d]\n", label, __func__, i);
		printf("encoded: %s\n", decoded_msg_to_str(orig));

		put = (struct osmo_gtlv_put){
			.cfg = cfg,
			.dst = msgb_alloc(1024, __func__),
		};
		rc = osmo_gtlvs_encode(&put, (void *)orig, sizeof(*orig), 0, msg_ie_coding,
				       err_cb, &verify_err_cb_data, tag_names);
		printf("osmo_gtlvs_encode() rc = %d\n", rc);
		printf("%s.\n", osmo_hexdump(put.dst->data, put.dst->len));

		load = (struct osmo_gtlv_load){
			.cfg = cfg,
			.src = { put.dst->data, put.dst->len },
		};
		rc = osmo_gtlvs_decode(&parsed, 0, &load, ordered, msg_ie_coding, err_cb, &verify_err_cb_data, tag_names);
		printf("osmo_gtlvs_decode() rc = %d\n", rc);
		printf("decoded: %s\n", decoded_msg_to_str(&parsed));
		if (strcmp(decoded_msg_to_str(orig), decoded_msg_to_str(&parsed))) {
			printf(" ERROR: parsed != orig\n");
			exit(1);
		}
		printf("=== end %s %s[%d]\n", label, __func__, i);
	}
}

int main()
{
	ctx = talloc_named_const(NULL, 0, "gtlv_test");
	msgb_talloc_ctx_init(ctx, 0);

	test_enc_dec("t8l8v ordered", &osmo_t8l8v_cfg, true);
	test_enc_dec("t8l8v unordered", &osmo_t8l8v_cfg, false);

	test_enc_dec("t16l16v ordered", &osmo_t16l16v_cfg, true);
	test_enc_dec("t16l16v unordered", &osmo_t16l16v_cfg, false);

	talloc_free(ctx);
	return 0;
}
