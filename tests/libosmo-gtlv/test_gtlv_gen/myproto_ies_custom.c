/* Example for defining custom IES for gtlv_gen. */
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

#include <errno.h>
#include <inttypes.h>

#include <osmocom/core/bits.h>
#include <osmocom/core/msgb.h>
#include <osmocom/gtlv/gtlv.h>

#include <myproto_ies_custom.h>

int myproto_dec_u16(void *decoded_struct, void *decode_to, const struct osmo_gtlv_load *gtlv)
{
	int *foo = decode_to;
	if (gtlv->len != 2)
		return -EINVAL;
	*foo = osmo_load16be(gtlv->val);
	return 0;
}

int myproto_enc_u16(struct osmo_gtlv_put *gtlv, void *decoded_struct, void *encode_from)
{
	int *foo = encode_from;
	if (*foo > INT16_MAX)
		return -EINVAL;
	msgb_put_u16(gtlv->dst, *foo);
	return 0;
}

int myproto_enc_to_str_u16(char *buf, size_t buflen, void *encode_from)
{
	int *foo = encode_from;
	return snprintf(buf, buflen, "%d", *foo);
}

int myproto_dec_u64(void *decoded_struct, void *decode_to, const struct osmo_gtlv_load *gtlv)
{
	uint64_t *val = decode_to;
	if (gtlv->len != sizeof(uint64_t))
		return -EINVAL;
	*val = osmo_load64be(gtlv->val);
	return 0;
}

int myproto_enc_u64(struct osmo_gtlv_put *gtlv, void *decoded_struct, void *encode_from)
{
	uint64_t *val = encode_from;
	osmo_store64be(*val, msgb_put(gtlv->dst, sizeof(*val)));
	return 0;
}

int myproto_enc_to_str_u64(char *buf, size_t buflen, void *encode_from)
{
	uint64_t *val = encode_from;
	return snprintf(buf, buflen, "0x%"PRIx64, *val);
}

int myproto_dec_bar(void *decoded_struct, void *decode_to, const struct osmo_gtlv_load *gtlv)
{
	struct myproto_ie_bar *bar = decode_to;
	if (gtlv->len > sizeof(bar->str) - 1)
		return -EINVAL;
	osmo_strlcpy(bar->str, (const char *)gtlv->val, OSMO_MIN(gtlv->len + 1, sizeof(bar->str)));
	return 0;
}

int myproto_enc_bar(struct osmo_gtlv_put *gtlv, void *decoded_struct, void *encode_from)
{
	struct myproto_ie_bar *bar = encode_from;
	int len = strnlen(bar->str, sizeof(bar->str));
	memcpy(msgb_put(gtlv->dst, len), bar, len);
	return 0;
}

int myproto_enc_to_str_bar(char *buf, size_t buflen, void *encode_from)
{
	struct myproto_ie_bar *bar = encode_from;
	return osmo_quote_str_buf3(buf, buflen, bar->str, -1);
}

int myproto_dec_baz(void *decoded_struct, void *decode_to, const struct osmo_gtlv_load *gtlv)
{
	struct myproto_ie_baz *baz = decode_to;
	uint16_t l;
	if (gtlv->len != 2)
		return -EINVAL;
	l = osmo_load16be(gtlv->val);
	baz->v_int = l & 0x7fff;
	baz->v_bool = (l & 0x8000) ? true : false;
	return 0;
}

int myproto_enc_baz(struct osmo_gtlv_put *gtlv, void *decoded_struct, void *encode_from)
{
	struct myproto_ie_baz *baz = encode_from;
	if (baz->v_int > 0x7fff)
		return -EINVAL;
	msgb_put_u16(gtlv->dst, (baz->v_bool ? 0x8000 : 0) + (baz->v_int & 0x7fff));
	return 0;
}

int myproto_enc_to_str_baz(char *buf, size_t buflen, void *encode_from)
{
	struct myproto_ie_baz *baz = encode_from;
	return snprintf(buf, buflen, "{%d,%s}", baz->v_int, baz->v_bool ? "true" : "false");
}

int myproto_dec_repeat_struct(void *decoded_struct, void *decode_to, const struct osmo_gtlv_load *gtlv)
{
	struct myproto_ie_repeat_struct *repeat_struct = decode_to;
	if (gtlv->len != 3)
		return -EINVAL;
	repeat_struct->v_int = osmo_load16be(gtlv->val);
	repeat_struct->v_bool = gtlv->val[2] & 0x80;
	repeat_struct->v_enum = gtlv->val[2] & 0x7f;
	return 0;
}

int myproto_enc_repeat_struct(struct osmo_gtlv_put *gtlv, void *decoded_struct, void *encode_from)
{
	struct myproto_ie_repeat_struct *repeat_struct = encode_from;
	msgb_put_u16(gtlv->dst, repeat_struct->v_int);
	msgb_put_u8(gtlv->dst, (repeat_struct->v_bool ? 0x80 : 0) + (repeat_struct->v_enum & 0x7f));
	return 0;
}

int myproto_enc_to_str_repeat_struct(char *buf, size_t buflen, void *encode_from)
{
	struct myproto_ie_repeat_struct *repeat_struct = encode_from;
	return snprintf(buf, buflen, "{%d,%s,%s}",
			repeat_struct->v_int, repeat_struct->v_bool ?  "true" : "false",
			get_value_string(myproto_repeat_enum_names, repeat_struct->v_enum));
}

const struct value_string myproto_msg_type_names[] = {
	{ MYPROTO_MSGT_MOO, "MOO" },
	{ MYPROTO_MSGT_GOO, "GOO" },
	{}
};

const struct value_string myproto_iei_names[] = {
	{ MYPROTO_IEI_FOO, "FOO" },
	{ MYPROTO_IEI_BAR, "BAR" },
	{ MYPROTO_IEI_BAZ, "BAZ" },
	{ MYPROTO_IEI_REPEAT_INT, "REPEAT_INT" },
	{ MYPROTO_IEI_REPEAT_STRUCT, "REPEAT_STRUCT" },
	{ MYPROTO_IEI_MOO_NEST, "MOO_NEST" },
	{ MYPROTO_IEI_VAL, "VAL" },
	{ MYPROTO_IEI_GOO_NEST, "GOO_NEST" },
	{}
};

const struct value_string myproto_repeat_enum_names[] = {
	OSMO_VALUE_STRING(R_A),
	OSMO_VALUE_STRING(R_B),
	OSMO_VALUE_STRING(R_C),
	{}
};
