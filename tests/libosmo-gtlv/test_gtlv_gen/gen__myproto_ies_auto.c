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

#include <stdbool.h>
#include <stdio.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/talloc.h>
#include <osmocom/gtlv/gtlv_gen.h>

#define O OSMO_GTLV_GEN_O
#define M OSMO_GTLV_GEN_M
#define O_MULTI OSMO_GTLV_GEN_O_MULTI
#define M_MULTI OSMO_GTLV_GEN_M_MULTI

#define ALL_FROM_NAME osmo_gtlv_gen_ie_auto

/* An IE where the type is not a 'struct myproto_ie_${name}'. */
static const struct osmo_gtlv_gen_ie number = {
	.decoded_type =	"int", /* add 'int foo;' to the struct */
	.dec_enc = "u16", /* use myproto_dec_u16() and myproto_enc_u16() for the TLV value part */
	.spec_ref = "an int coded as uint16_t",
};

static const struct osmo_gtlv_gen_ie_o ies_in_moo_nest[] = {
	/* Mandatory member xxx.foo of the type defined in 'number' above. */
	M(number, "foo"),
	/* Mandatory member xxx.bar of type 'struct myproto_ie_bar', using myproto_ie_dec_bar(), myproto_ie_enc_bar(),
	 * myproto_ie_enc_to_str_bar(), all defined in myproto_ies_custom.h/c. */
	M(ALL_FROM_NAME, "bar"),
	M(ALL_FROM_NAME, "baz"),
	{}
};

static const struct osmo_gtlv_gen_ie huge_number = {
	.decoded_type =	"uint64_t",
	.dec_enc = "u64",
};

static const struct osmo_gtlv_gen_ie moo_nest = {
	.tag_name = "moo_nest",
	.nested_ies = ies_in_moo_nest,
};

static const struct osmo_gtlv_gen_ie_o ies_in_goo_nest[] = {
	O(huge_number, "val"),
	M(moo_nest, "nest"),
	{}
};

static const struct osmo_gtlv_gen_ie goo_nest = {
	.tag_name = "goo_nest",
	.nested_ies = ies_in_goo_nest,
};

static const struct osmo_gtlv_gen_ie_o ies_in_moo_msg[] = {
	M(number, "foo"),
	M(ALL_FROM_NAME, "bar"),
	O(ALL_FROM_NAME, "baz"),
	O_MULTI(32, number, "repeat_int"),
	O_MULTI(32, ALL_FROM_NAME, "repeat_struct"),
	O(moo_nest, "nest"),
	{}
};

static const struct osmo_gtlv_gen_ie_o ies_in_goo_msg[] = {
	M(number, "foo"),
	O(ALL_FROM_NAME, "bar"),
	O_MULTI(8, goo_nest, "nest"),
	{}
};

static const struct osmo_gtlv_gen_msg msg_defs[] = {
	{ "moo", ies_in_moo_msg },
	{ "goo", ies_in_goo_msg },
	{}
};

int main(int argc, const char **argv)
{
	struct osmo_gtlv_gen_cfg cfg = {
		.proto_name = "myproto",
		.message_type_enum = "enum myproto_msg_type",
		.message_type_prefix = "MYPROTO_MSGT_",
		.tag_enum = "enum myproto_iei",
		.tag_prefix = "MYPROTO_IEI_",
		.decoded_type_prefix = "struct myproto_ie_",
		.h_header = "#include \"myproto_ies_custom.h\"",
		.c_header = "#include <myproto_ies_auto.h>",
		.msg_defs = msg_defs,
		.add_enc_to_str = true,
	};
	return osmo_gtlv_gen_main(&cfg, argc, argv);
}
