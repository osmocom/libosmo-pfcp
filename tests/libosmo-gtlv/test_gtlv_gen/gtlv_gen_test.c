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

#include <osmocom/core/application.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/msgb.h>

#include <osmocom/gtlv/gtlv.h>

#include <myproto_ies_auto.h>

struct myproto_msg {
	enum myproto_msg_type type;
	union myproto_ies ies;
};

static void err_cb(void *data, void *decoded_struct, const char *file, int line, const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	//printf("ERR: %s:%d ", file, line);
	printf("ERR: ");
	vprintf(fmt, args);
	va_end(args);
}

static int myproto_msg_enc(struct msgb *dst, const struct myproto_msg *msg, const struct osmo_gtlv_cfg *cfg)
{
	struct osmo_gtlv_put gtlv = {
		.cfg = cfg,
		.dst = dst,
	};

	msgb_put_u8(gtlv.dst, msg->type);
	return myproto_ies_encode(&gtlv, (void *)&msg->ies, msg->type, err_cb, NULL, myproto_iei_names);
}

static int myproto_msg_dec(struct myproto_msg *msg, const uint8_t *data, size_t data_len,
			   const struct osmo_gtlv_cfg *cfg, bool ordered)
{
	struct osmo_gtlv_load gtlv;
	if (data_len < 1)
		return -EINVAL;
	msg->type = data[0];
	gtlv = (struct osmo_gtlv_load){
		.cfg = cfg,
		.src = { data + 1, data_len - 1 },
	};
	return myproto_ies_decode(&msg->ies, &gtlv, ordered, msg->type, err_cb, NULL, myproto_iei_names);
}

void *ctx;

struct myproto_msg tests[] = {
	{
		MYPROTO_MSGT_MOO,
		{
			.moo = {
				.foo = 23,
				.bar = { "twentythree" },
			},
		},
	},
	{
		MYPROTO_MSGT_MOO,
		{
			.moo = {
				.foo = 23,
				.bar = { "twentythree" },

				.baz_present = true,
				.baz = {
					.v_int = 2323,
					.v_bool = true,
				},
			},
		},
	},
	{
		MYPROTO_MSGT_MOO,
		{
			.moo = {
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
		},
	},
	{
		MYPROTO_MSGT_MOO,
		{
			.moo = {
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
		},
	},
	{
		MYPROTO_MSGT_GOO,
		{
			.goo = {
				.foo = 17,

				.bar_present = true,
				.bar = { "gooei" },

				.nest_count = 2,
				.nest = {
					{
						.val_present = true,
						.val = 0x0123456789abcdef,
						.nest = {
							.foo = 11,
							.bar = { "eleven" },
							.baz = {
								.v_int = 1111,
								.v_bool = true,
							},
						},
					},
					{
						.val_present = false,
						.nest = {
							.foo = 12,
							.bar = { "twelve" },
							.baz = {
								.v_int = 1212,
								.v_bool = false,
							},
						},
					},
				},
			},
		},
	},
};

int myproto_msg_to_str_buf(char *buf, size_t buflen, const struct myproto_msg *m)
{
	struct osmo_strbuf sb = { .buf = buf, .len = buflen };
	OSMO_STRBUF_PRINTF(sb, "%s={", get_value_string(myproto_msg_type_names, m->type));
	OSMO_STRBUF_APPEND(sb, osmo_gtlvs_encode_to_str_buf, &m->ies, sizeof(m->ies), 0,
			   myproto_get_msg_coding(m->type), myproto_iei_names);
	OSMO_STRBUF_PRINTF(sb, " }");
	return sb.chars_needed;

}

char *myproto_msg_to_str(const struct myproto_msg *m)
{
	OSMO_NAME_C_IMPL(ctx, 256, "ERROR", myproto_msg_to_str_buf, m)
}

void test_enc_dec(const char *label, const struct osmo_gtlv_cfg *cfg, bool ordered)
{
	int i;
	for (i = 0; i < ARRAY_SIZE(tests); i++) {
		int rc;
		const struct myproto_msg *orig = &tests[i];
		struct myproto_msg parsed = {};
		struct msgb *msg;

		printf("\n=== start %s %s[%d]\n", label, __func__, i);
		printf("encoded: %s\n", myproto_msg_to_str(orig));

		msg = msgb_alloc(1024, __func__);
		rc = myproto_msg_enc(msg, orig, cfg);
		printf("myproto_msg_enc() rc = %d\n", rc);
		printf("%s.\n", osmo_hexdump(msg->data, msg->len));

		rc = myproto_msg_dec(&parsed, msg->data, msg->len, cfg, ordered);
		printf("myproto_msg_dec() rc = %d\n", rc);
		printf("decoded: %s\n", myproto_msg_to_str(&parsed));
		if (strcmp(myproto_msg_to_str(orig), myproto_msg_to_str(&parsed))) {
			printf(" ERROR: parsed != orig\n");
			exit(1);
		}

		msgb_free(msg);
		printf("=== end %s %s[%d]\n", label, __func__, i);
	}
}

int main()
{
	ctx = talloc_named_const(NULL, 0, "test_gen_tlv");
	msgb_talloc_ctx_init(ctx, 0);

	test_enc_dec("t8l8v ordered", &osmo_t8l8v_cfg, true);
	test_enc_dec("t8l8v unordered", &osmo_t8l8v_cfg, false);

	test_enc_dec("t16l16v ordered", &osmo_t16l16v_cfg, true);
	test_enc_dec("t16l16v unordered", &osmo_t16l16v_cfg, false);

	talloc_free(ctx);
	return 0;
}
