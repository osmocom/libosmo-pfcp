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
#define O_INST OSMO_GTLV_GEN_O_INST
#define M_INST OSMO_GTLV_GEN_M_INST

#define AUTO osmo_gtlv_gen_ie_auto

static const struct osmo_gtlv_gen_ie bar = {
	.tag_name = "bar",
};

static const struct osmo_gtlv_gen_ie_o ies_in_moo_msg[] = {
	M_INST("MYPROTO_IEI_BAR_ALPHA", bar, "bar_alpha"),
	O_INST("MYPROTO_IEI_BAR_BETA", bar, "bar_beta"),
	M_INST("MYPROTO_IEI_BAR_GAMMA", bar, "bar_gamma"),
	{}
};

static const struct osmo_gtlv_gen_msg msg_defs[] = {
	{ "moo", ies_in_moo_msg },
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
