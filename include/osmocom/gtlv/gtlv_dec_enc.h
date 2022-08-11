/* Decode and encode the value parts of a TLV structure */
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

#include <osmocom/gtlv/gtlv.h>

struct value_string;

/* User defined function to decode a single TLV value part. See struct osmo_gtlv_coding.
 * \param decoded_struct  Pointer to the root struct, as context information, e.g. for logging.
 * \param decode_to  Pointer to the struct member, write the decoded value here.
 * \param gtlv  TLV loader, pointing at a gtlv->val of gtlv->len bytes.
 * \return 0 on success, nonzero on error, e.g. -EINVAL if the gtlv->val is invalid.
 */
typedef int (*osmo_gtlv_dec_func)(void *decoded_struct, void *decode_to, const struct osmo_gtlv_load *gtlv);

/* User defined function to encode a single TLV value part. See struct osmo_gtlv_coding.
 * \param gtlv  TLV writer, pointing at a gtlv->dst to msgb_put() data in.
 * \param decoded_struct  Pointer to the root struct, as context information, e.g. for logging.
 * \param encode_from  Pointer to the struct member, obtain the value to encode from here.
 * \return 0 on success, nonzero on error, e.g. -EINVAL if encode_from has an un-encodable value.
 */
typedef int (*osmo_gtlv_enc_func)(struct osmo_gtlv_put *gtlv, const void *decoded_struct, const void *encode_from);

/* Optional user defined function to convert a decoded IE struct (the Value part stored as C struct) to string. See
 * struct osmo_gtlv_coding.
 * \param buf  Return string in this buffer.
 * \param buflen  Size of buf.
 * \param str_of  Pointer to the struct member described by an osmo_gtlv_coding, obtain the value to encode from here.
 * \return number of characters that would be written if the buffer is large enough, like snprintf().
 */
typedef int (*osmo_gtlv_enc_to_str_func)(char *buf, size_t buflen, const void *str_of);

/* Whether TLV structures nested inside the value data of an outer IE should be parsed in the same order. */
enum osmo_gtlv_coding_nested_ies_ordered {
	/*! When stepping into nested IEs, keep the same ordering requirement as the outer IE. */
	OSMO_GTLV_NESTED_IES_ORDERING_SAME = 0,
	/*! Require IEs in a PDU to appear exactly in the order defined by osmo_gtlv_coding arrays. Causes a parsing
	 * failure if the TLVs appear in a different order. Does much less iterating looking for matching tags when
	 * decoding (faster). */
	OSMO_GTLV_NESTED_IES_ORDERED,
	/*! Do not require IEs to be in the defined order in decoded PDUs. When encoding a TLV, IEs will always be
	 * encoded in the order they are defined. This has an effect on decoding only. */
	OSMO_GTLV_NESTED_IES_UNORDERED,
};

#define OSMO_ARRAY_PITCH(arr) ((char *)(&(arr)[1]) - (char *)(arr))
#define OSMO_MEMB_ARRAY_PITCH(obj_type, arr_memb) OSMO_ARRAY_PITCH(((obj_type *)0)->arr_memb)

/*! Definition of how to decode/encode a IE to/from a struct.
 * Kept in lists describing TLV structures, and nestable.
 *
 * Instance lists of this can be composed manually, or auto-generated using gtlv_gen.c. Auto-generating has the benefit
 * that the decoded structs to match the IEs are also generated at the same time and thus always match the message
 * definitions. For an example, see tests/libosmo-gtlv/test_gtlv_gen/. */
struct osmo_gtlv_coding {
	/*! the IEI discriminator, and optional instance number */
	struct osmo_gtlv_tag_inst ti;

	/*! Decoding function callback. Invoked for each defined and present IE encountered in the message.
	 * Return 0 on success, negative on failure. */
	osmo_gtlv_dec_func dec_func;
	/*! Encoding function callback. Invoked for each defined and present IE encountered in the message.
	 * Return 0 on success, negative on failure. */
	osmo_gtlv_enc_func enc_func;

	/*! Means to output the decoded value to a human readable string, optional. */
	osmo_gtlv_enc_to_str_func enc_to_str_func;

	/*! offsetof(decoded_struct_type, member_var): how far into the base struct you find a specific field for decoded
	 * value. For example, memb_ofs = offsetof(struct foo_msg, ies.bar_response.cause).
	 * When decoding, the decoded value is written here, when encoding it is read from here. */
	unsigned int memb_ofs;
	/*! For repeated IEs (.has_count = true), the array pitch / the offset to add to get to the next array index. */
	unsigned int memb_array_pitch;

	/*! True for optional/conditional IEs. */
	bool has_presence_flag;
	/* For optional/conditional IEs (has_presence_flag = true), the offset of the bool foo_present flag,
	 * For example, if there are
	 *
	 * struct foo_msg {
	 *         struct baz baz;
	 *         bool baz_present;
	 * };
	 *
	 * then set
	 * memb_ofs = offsetof(struct foo_msg, baz);
	 * has_presence_flag = true;
	 * presence_flag_ofs = offsetof(struct foo_msg, baz_present);
	 */
	unsigned int presence_flag_ofs;

	/*! True for repeated IEs, for array members:
	 *
	 * struct foo_msg {
	 *         struct moo moo[10];
	 *         unsigned int moo_count;
	 * };
	 *
	 * memb_ofs = offsetof(struct foo_msg, moo);
	 * has_count = true;
	 * count_ofs = offsetof(struct foo_msg, moo_count);
	 * count_max = 10;
	 */
	bool has_count;
	/*! For repeated IEs, the offset of the unsigned int foo_count indicator of how many array indexes are
	 * in use. See has_count. */
	unsigned int count_ofs;
	/*! Maximum array size for member_var[]. See has_count. */
	unsigned int count_max;
	/*! If nonzero, it is an error when less than this amount of the repeated IE have been decoded. */
	unsigned int count_mandatory;

	/*! For nested TLVs: if this IE's value part is itself a separate TLV structure, point this at the list of IE
	 * coding definitions for the inner IEs.
	 * In this example, the nested IEs decode/encode to different sub structs depending on the tag value.
	 *
	 *     struct bar {
	 *             int aaa;
	 *             int bbb;
	 *     };
	 *
	 *     struct foo_msg {
	 *             struct bar bar;
	 *             struct bar other_bar;
	 *     };
	 *
	 *     struct osmo_gtlv_coding bar_nested_ies[] = {
	 *             { FOO_IEI_AAA, .memb_ofs = offsetof(struct bar, aaa), },
	 *             { FOO_IEI_BBB, .memb_ofs = offsetof(struct bar, bbb), },
	 *             {}
	 *     };
	 *
	 *     struct osmo_gtlv_coding foo_msg_ies[] = {
	 *             { FOO_IEI_GOO, .memb_ofs = offsetof(struct foo_msg, bar), .nested_ies = bar_nested_ies, },
	 *             { FOO_IEI_OTHER_GOO, .memb_ofs = offsetof(struct foo_msg, other_bar), .nested_ies = bar_nested_ies, },
	 *             {}
	 *     };
	 */
	const struct osmo_gtlv_coding *nested_ies;

	/*! If the nested TLV has a different tag/length size than the outer TLV structure, provide a different config
	 * here. If they are the same, just keep this NULL. */
	const struct osmo_gtlv_cfg *nested_ies_cfg;

	/*! When stepping into nested IEs, what is the ordering requirement for the nested TLV structure? */
	enum osmo_gtlv_coding_nested_ies_ordered nested_ies_ordered;
};


/*! User defined hook for error logging during TLV and value decoding.
 * \param decoded_struct  Pointer to the base struct describing this message, for context.
 * \param file  Source file of where the error occurred.
 * \param line  Source file line of where the error occurred.
 * \param fmt  Error message string format.
 * \param ...  Error message string args.
 */
typedef void (*osmo_gtlv_err_cb)(void *data, void *decoded_struct, const char *file, int line, const char *fmt, ...);

int osmo_gtlvs_decode(void *decoded_struct, size_t decoded_struct_size,
		      unsigned int obj_ofs, struct osmo_gtlv_load *gtlv, bool tlv_ordered,
		      const struct osmo_gtlv_coding *ie_coding,
		      osmo_gtlv_err_cb err_cb, void *err_cb_data, const struct value_string *iei_strs);

int osmo_gtlvs_encode(struct osmo_gtlv_put *gtlv, const void *decoded_struct, size_t decoded_struct_size,
		      unsigned int obj_ofs, const struct osmo_gtlv_coding *ie_coding, osmo_gtlv_err_cb err_cb,
		      void *err_cb_data, const struct value_string *iei_strs);

int osmo_gtlvs_encode_to_str_buf(char *buf, size_t buflen, const void *decoded_struct, unsigned int obj_ofs,
				const struct osmo_gtlv_coding *ie_coding, const struct value_string *iei_strs);
char *osmo_gtlvs_encode_to_str_c(void *ctx, const void *decoded_struct, unsigned int obj_ofs,
				const struct osmo_gtlv_coding *ie_coding, const struct value_string *iei_strs);

static inline bool osmo_gtlv_coding_end(const struct osmo_gtlv_coding *iec)
{
	return iec->dec_func == NULL && iec->enc_func == NULL && iec->nested_ies == NULL;
}
