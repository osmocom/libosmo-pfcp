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
				.bar_alpha = { 23, true },
				.bar_gamma = { 42, false },
			},
		},
	},
	{
		MYPROTO_MSGT_MOO,
		{
			.moo = {
				.bar_alpha = { 11, true },
				.bar_beta_present = true,
				.bar_beta = { 22, false },
				.bar_gamma = { 33, true },
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

/* Example of defining a TLI, with an instance indicator */
static int tliv_load_tl(struct osmo_gtlv_load *gtlv, const uint8_t *src_data, size_t src_data_len)
{
	/* already validated in next_tl_valid(): src_data_len >= cfg->tl_min_size == 2. */
	gtlv->ti.tag = src_data[0];
	gtlv->len = src_data[1];

	switch (gtlv->ti.tag) {
	/* All tags that are TLIV go here */
	case MYPROTO_IEI_BAR:
		if (src_data_len < 3)
			return -ENOSPC;
		gtlv->ti.instance_present = true;
		gtlv->ti.instance = src_data[2];
		gtlv->val = src_data + 3;
		/* In this example, the I is part of the len */
		gtlv->len--;
		return 0;
	default:
		gtlv->val = src_data + 2;
		return 0;
	}
}

static int tliv_store_tl(uint8_t *dst_data, size_t dst_data_avail, const struct osmo_gtlv_tag_inst *ti, size_t len,
			 struct osmo_gtlv_put *gtlv)
{
	if (ti->tag > UINT8_MAX)
		return -EINVAL;
	if (len > UINT8_MAX)
		return -EMSGSIZE;
	if (dst_data_avail < 2)
		return -ENOSPC;

	dst_data[0] = ti->tag;

	switch (ti->tag) {
	/* All tags that are TLIV go here */
	case MYPROTO_IEI_BAR:
		if (dst_data_avail < 3)
			return -ENOSPC;
		if (!ti->instance_present)
			return -EINVAL;
		if (ti->instance > UINT8_MAX)
			return -EINVAL;
		/* here, I is part of the len in L; the passed len reflects only the value, so add 1 for I */
		dst_data[1] = len + 1;
		dst_data[2] = ti->instance;
		return 3;
	default:
		dst_data[1] = len;
		return 2;
	}
}

const struct osmo_gtlv_cfg osmo_tliv_cfg = {
	.tl_min_size = 2,
	.load_tl = tliv_load_tl,
	.store_tl = tliv_store_tl,
};

int main()
{
	ctx = talloc_named_const(NULL, 0, "test_gen_tlv");
	msgb_talloc_ctx_init(ctx, 0);

	test_enc_dec("tliv ordered", &osmo_tliv_cfg, true);
	test_enc_dec("tliv unordered", &osmo_tliv_cfg, false);

	talloc_free(ctx);
	return 0;
}
