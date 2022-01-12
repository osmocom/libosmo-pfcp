/* Write h and c source files for TLV protocol definitions, based on very sparse TLV definitions.
 * For a usage example see tests/libosmo-gtlv/test_gtlv_gen/. */
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

#pragma once

#include <stdbool.h>

struct osmo_gtlv_gen_ie;

/* O means optional, M means mandatory.
 * If all of the IE struct, tag name and functions can be derived from the name, just pass osmo_gtlv_gen_ie_auto as
 * TLV_GEN_IE. */
#define OSMO_GTLV_GEN_O(TLV_GEN_IE, MEMB_NAME) { MEMB_NAME, .optional = true, .ie = &(TLV_GEN_IE) }
#define OSMO_GTLV_GEN_M(TLV_GEN_IE, MEMB_NAME) { MEMB_NAME, .ie = &(TLV_GEN_IE) }
#define OSMO_GTLV_GEN_O_MULTI(MAX, TLV_GEN_IE, MEMB_NAME) { MEMB_NAME, .multi = MAX, .ie = &(TLV_GEN_IE) }
#define OSMO_GTLV_GEN_M_MULTI(MAX, MAND_COUNT, TLV_GEN_IE, MEMB_NAME) \
	{ MEMB_NAME, .multi = MAX, .multi_mandatory = MAND_COUNT, .ie = &(TLV_GEN_IE) }

/*! osmo_gtlv_gen_ie with all members == NULL, so that all are derived from the member name. */
extern const struct osmo_gtlv_gen_ie osmo_gtlv_gen_ie_auto;

/*! Modifier for Mandatory/Optional/Multiple around an osmo_gtlv_gen_ie. */
struct osmo_gtlv_gen_ie_o {
	/*! The C name of the member in a decoded struct, to be of the type defined by .ie.
	 * All parts of .ie, if NULL, are derived from this name.
	 *
	 * For example, simply this
	 *
	 *   struct osmo_gtlv_gen_ie_o foo[] = {
	 *       OSMO_GTLV_GEN_O("bar", NULL),
	 *   };
	 *
	 * Generates
	 *
	 *   struct myproto_msg_foo {
	 *       struct myproto_ie_bar bar;
	 *   }
	 *
	 * and an osmo_gtlv_coding entry of
	 *
	 * { MYPROTO_IEI_BAR,
	 *   .memb_ofs = offsetof(struct myproto_msg_foo, bar),
	 *   .dec_func = myproto_dec_bar,
	 *   .enc_func = myproto_enc_bar,
	 *   .enc_to_str_func = myproto_enc_to_str_bar,
	 * }
	 *
	 * See also osmo_gtlv_gen_cfg.add_enc_to_str.
	 */
	const char *name;

	/*! Whether to add a bool foo_present, and to skip encoding/decoding if false.
	 * Only useful for non-multi IEs (compare OSMO_GTLV_GEN_O_MULTI() vs OSMO_GTLV_GEN_M_MULTI()). */
	bool optional;

	/*! If non-NULL, the member is an array: foo[123] with an unsigned int foo_count.
	 * Set to the maximum number of array elements; for foo[123] set .multi = 123. */
	unsigned int multi;
	/*! Number of mandatory occurences of the IE, only has an effect if .multi > 0. */
	unsigned int multi_mandatory;

	/*! IE decoding / encoding instructions. If NULL, the entire IE definition is derived from .name.
	 * 'MYPROTO_IEI_NAME', 'myproto_dec_name()', 'myproto_enc_name()', 'myproto_enc_to_str_name()'.
	 * Your myproto_ies_custom.h needs to define an enum value MYPROTO_IEI_NAME and*/
	const struct osmo_gtlv_gen_ie *ie;
};

/*! Define decoding and encoding of a single IE, i.e. one full TLV. */
struct osmo_gtlv_gen_ie {
	/*! like "uint32_t" or "struct foo".
	 * If NULL, use "struct myproto_ie_<name>" instead, where <name> comes from the osmo_gtlv_gen_ie_o.
	 * When there are nested IEs, the struct definition is auto-generated, deriving the struct members from the
	 * nested_ies list.
	 * When there are no nested IEs, the type needs to be defined manually by a myproto_ies_custom.h. */
	const char *decoded_type;

	/*! C name of this tag value, e.g. "MYPROTO_IEI_FOO". If NULL, take "MYPROTO_IEI_"+upper(name) instead. */
	const char *tag_name;

	/*! Name suffix of the dec/enc functions. "foo" -> myproto_dec_foo(), myproto_enc_foo(),
	 * myproto_enc_to_str_foo().
	 * These functions need to be implemented manually in a myproto_ies_custom.c.
	 * When osmo_gtlv_gen_cfg.add_enc_to_str is false, the myproto_enc_to_str_foo() is not required. */
	const char *dec_enc;

	/*! List of inner IEs terminated by {}. If non-NULL, this is a "Grouped IE" with an inner TLV structure inside
	 * this IE's V part. */
	const struct osmo_gtlv_gen_ie_o *nested_ies;

	/*! To place a spec comment in the generated code. */
	const char *spec_ref;
};

/*! General TLV decoding and encoding definitions applying to all IEs (and nested IEs). */
struct osmo_gtlv_gen_cfg {
	/*! Name of the protocol for use in C type or function names, like "myproto". */
	const char *proto_name;

	/*! When placing comments to spec references, prefix with this. For example, "3GPP TS 12.345 ". */
	const char *spec_ref_prefix;

	/*! The type to pass a message discriminator as, like 'enum myproto_message_types' */
	const char *message_type_enum;
	/*! To reference a message type discriminator like MYPROTO_MSGT_FOO, this would be "MYPROTO_MSGT_". */
	const char *message_type_prefix;

	/*! Type to use to represent tag IEI in decoded form.
	 * For example "enum foo_msg_iei". */
	const char *tag_enum;
	/*! The tag IEI enum value is uppercase(tag_prefix + (iedef->tag_name or iedef->name)).
	 * For example, with tag_prefix = "OSMO_FOO_IEI_", we would generate code like
	 * enum osmo_foo_iei tag = OSMO_FOO_IEI_BAR; */
	const char *tag_prefix;

	/*! When an osmo_gtlv_gen_ie provides no decoded_type string, it is derived from .name and this prefix is
	 * added. For example, with decoded_type_prefix = "struct foo_ie_", the decoded_type defaults to
	 * struct foo_ie_bar for an IE definition with name = "bar". */
	const char *decoded_type_prefix;

	/*! To include user defined headers, set to something like "#include <osmocom/foo/foo_tlv_devs.h". This is put at
	 * the head of the generated .h file. */
	const char *h_header;

	/*! To include user defined headers, set to something like "#include <osmocom/foo/foo_msg.h". This is put at
	 * the head of the generated .c file. */
	const char *c_header;

	/*! Array of message IE definitions, indexed by message type. */
	const struct osmo_gtlv_gen_msg *msg_defs;

	/*! Whether to add to_str functions. When true, every automatically derived IE (that has no nested IEs) needs to
	 * have a myproto_enc_to_str_foo() defined by a myproto_ies_custom.c. When false, osmo_gtlvs_encode_to_str_buf()
	 * will print '?' instead of the IE contents. */
	bool add_enc_to_str;
};

/*! For generating the outer union that composes a protocol's PDU variants, an entry of the list of message names and
 * IEs in each message. */
struct osmo_gtlv_gen_msg {
	const char *name;
	const struct osmo_gtlv_gen_ie_o *ies;
};

int osmo_gtlv_gen_main(const struct osmo_gtlv_gen_cfg *cfg, int argc, const char **argv);
