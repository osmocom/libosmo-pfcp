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

int myproto_dec_bar(void *decoded_struct, void *decode_to, const struct osmo_gtlv_load *gtlv)
{
	struct myproto_ie_bar *bar = decode_to;
	if (gtlv->len < 2)
		return -EINVAL;
	*bar = (struct myproto_ie_bar){
		.a = gtlv->val[0],
		.b = (gtlv->val[1] == 1),
	};
	return 0;
}

int myproto_enc_bar(struct osmo_gtlv_put *gtlv, void *decoded_struct, void *encode_from)
{
	struct myproto_ie_bar *bar = encode_from;
	msgb_put_u8(gtlv->dst, bar->a);
	msgb_put_u8(gtlv->dst, bar->b ? 1 : 0);
	return 0;
}

int myproto_enc_to_str_bar(char *buf, size_t buflen, void *encode_from)
{
	struct myproto_ie_bar *bar = encode_from;
	return snprintf(buf, buflen, "%d,%s", bar->a, bar->b ? "true" : "false");
}

const struct value_string myproto_msg_type_names[] = {
	{ MYPROTO_MSGT_MOO, "MOO" },
	{}
};

const struct value_string myproto_iei_names[] = {
	{ MYPROTO_IEI_BAR, "BAR" },
	{}
};
