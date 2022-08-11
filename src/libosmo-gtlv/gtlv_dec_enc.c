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
#include <string.h>

#include <osmocom/core/utils.h>

#include <osmocom/gtlv/gtlv_dec_enc.h>

/* Reverse offsetof(): return the address of the struct member for a given osmo_gtlv_msg and member ofs_foo value. */
#define MEMB(M, MEMB_OFS) ((void *)((char *)(M) + (MEMB_OFS)))

#define RETURN_ERROR(RC, TAG_INST, FMT, ARGS...) \
	do {\
		if (err_cb) { \
			if ((TAG_INST).instance_present) \
				err_cb(err_cb_data, (void *)decoded_struct, __FILE__, __LINE__, \
				       "tag 0x%x = %s instance %u: " FMT " (%d: %s)\n", \
				       (TAG_INST).tag, get_value_string(iei_strs, (TAG_INST).tag), \
				       (TAG_INST).instance, ##ARGS, \
				       RC, strerror((RC) > 0 ? (RC) : -(RC))); \
			else \
				err_cb(err_cb_data, (void *)decoded_struct, __FILE__, __LINE__, \
				       "tag 0x%x = %s: " FMT " (%d: %s)\n", \
				       (TAG_INST).tag, get_value_string(iei_strs, (TAG_INST).tag), ##ARGS, \
				       RC, strerror((RC) > 0 ? (RC) : -(RC))); \
		} \
		return RC; \
	} while (0)


/*! Decode a TLV structure from raw data to a decoded struct, for unordered TLV IEs.
 * How to decode IE values and where to place them in the decoded struct, is defined by ie_coding, an array terminated
 * by a '{}' entry.
 * The IEs may appear in any ordering in the TLV data.
 * For unordered decoding, only IEs with has_presence_flag == true or has_count == true may repeat. Other IE definitions
 * cause the last read TLV to overwrite all previous decodings, all into the first occurrence in ie_coding.
 * \param[out] decoded_struct  Pointer to the struct to write parsed IE data to.
 * \param[in] obj_ofs  Pass as zero. Used for nested IEs: offset added to decoded_struct to get to a sub-struct.
 * \param[in] gtlv  TLV data to parse, as given in gtlv->msg.*. Must be ready for osmo_gtlv_load_start().
 * \param[in] ie_coding  A list of permitted/expected IEI tags and instructions for decoding.
 * \param[in] err_cb  Function to call to report an error message, or NULL.
 * \param[in] err_cb_data  Caller supplied context to pass to the err_cb as 'data' argument.
 * \param[in] iei_strs  value_string array to give IEI names in error messages passed to err_cb(), or NULL.
 * \return 0 on success, negative on error.
 */
static int osmo_gtlvs_decode_unordered(void *decoded_struct, unsigned int obj_ofs, struct osmo_gtlv_load *gtlv,
				      const struct osmo_gtlv_coding *ie_coding,
				      osmo_gtlv_err_cb err_cb, void *err_cb_data, const struct value_string *iei_strs)
{
	void *obj = MEMB(decoded_struct, obj_ofs);
	const struct osmo_gtlv_coding *iec;
	unsigned int *multi_count_p = NULL;

	/* To check for presence of mandatory IEs, need to keep a flag stack of seen ie_coding entries. This array has
	 * to have at least the nr of entries that the ie_coding array has. Let's allow up to this many ie_coding
	 * entries to avoid dynamic allocation. Seems like enough. */
	bool seen_ie_coding_entries[4096] = {};
	bool *seen_p;
#define CHECK_SEEN(IEC) do { \
			unsigned int ie_coding_idx = (IEC) - ie_coding; \
			if (ie_coding_idx >= ARRAY_SIZE(seen_ie_coding_entries)) \
				RETURN_ERROR(-ENOTSUP, gtlv->ti, \
					     "Too many IE definitions for decoding an unordered TLV structure"); \
			seen_p = &seen_ie_coding_entries[ie_coding_idx]; \
		} while (0)


	osmo_gtlv_load_start(gtlv);

	/* IEs are allowed to come in any order.  So traverse the TLV structure once, and find an IE parser for each (if
	 * any). */
	for (;;) {
		int rc;
		bool *presence_flag_p;
		unsigned int memb_next_array_idx;
		unsigned int memb_ofs;
		unsigned int ie_max_allowed_count;

		rc = osmo_gtlv_load_next(gtlv);
		if (rc)
			RETURN_ERROR(rc, gtlv->ti, "Decoding IEs failed on or after this tag");
		if (!gtlv->val) {
			/* End of the TLV structure */
			break;
		}

		/* ie_max_allowed_count counts how often the same IEI may appear in a message until all struct members
		 * that can store them are filled up. */
		ie_max_allowed_count = 0;

		do {
			/* Find the IE coding for this tag */
			for (iec = ie_coding;
			     !osmo_gtlv_coding_end(iec) && osmo_gtlv_tag_inst_cmp(&iec->ti, &gtlv->ti);
			     iec++);
			/* No such IE coding found. */
			if (osmo_gtlv_coding_end(iec))
				break;

			/* Keep track how often this tag can occur */
			ie_max_allowed_count += iec->has_count ? iec->count_max : 1;

			/* Was this iec instance already decoded? Then skip to the next one, if any. */
			presence_flag_p = iec->has_presence_flag ? MEMB(obj, iec->presence_flag_ofs) : NULL;
			multi_count_p = iec->has_count ? MEMB(obj, iec->count_ofs) : NULL;
			if ((presence_flag_p && *presence_flag_p)
			    || (multi_count_p && *multi_count_p >= iec->count_max))
				continue;
			/* For IEs with a presence flag or a multi count, the decoded struct provides the information
			 * whether the IE has already been decoded. Do the same for mandatory IEs, using local state in
			 * seen_ie_coding_entries[]. */
			CHECK_SEEN(iec);
			if (*seen_p)
				continue;
		} while (0);
		if (osmo_gtlv_coding_end(iec)) {
			if (ie_max_allowed_count) {
				/* There have been IE definitions for this IEI, but all slots to decode it are already
				 * filled. */
				RETURN_ERROR(-ENOTSUP, gtlv->ti, "Only %u instances of this IE are supported per message",
					     ie_max_allowed_count);
			}
			/* No such IE defined in ie_coding, just skip the TLV. */
			continue;
		}

		/* If this is a repeated IE, decode into the correct array index memb[idx],
		 * next idx == (*multi_count_p). We've already guaranteed above that *multi_count_p < count_max. */
		memb_next_array_idx = multi_count_p ? *multi_count_p : 0;
		memb_ofs = iec->memb_ofs + memb_next_array_idx * iec->memb_array_pitch;

		/* Decode IE value part */
		if (iec->nested_ies) {
			/* A nested IE: the value part of this TLV is in turn a TLV structure. Decode the inner
			 * IEs. */
			struct osmo_gtlv_load inner_tlv = {
				.cfg = iec->nested_ies_cfg ? : gtlv->cfg,
				.src = {
					.data = gtlv->val,
					.len = gtlv->len,
				}
			};
			bool ordered;
			switch (iec->nested_ies_ordered) {
			case OSMO_GTLV_NESTED_IES_ORDERED:
				ordered = true;
				break;
			case OSMO_GTLV_NESTED_IES_ORDERING_SAME:
			case OSMO_GTLV_NESTED_IES_UNORDERED:
				ordered = false;
				break;
			default:
				OSMO_ASSERT(0);
			}
			rc = osmo_gtlvs_decode(decoded_struct, obj_ofs + memb_ofs, &inner_tlv, ordered, iec->nested_ies,
					      err_cb, err_cb_data, iei_strs);
			if (rc)
				RETURN_ERROR(rc, gtlv->ti, "Error while decoding TLV structure nested inside this IE");
		} else {
			/* Normal IE, decode the specific IE data. */
			if (!iec->dec_func)
				RETURN_ERROR(-EIO, gtlv->ti, "IE definition lacks a dec_func()");
			rc = iec->dec_func(decoded_struct, MEMB(obj, memb_ofs), gtlv);
			if (rc)
				RETURN_ERROR(rc, gtlv->ti, "Error while decoding this IE");
		}

		if (multi_count_p) {
			/* A repeated IE, record that we've added one entry. This increments the foo_count value in the
			 * decoded osmo_gtlv_msg.ies.*.
			 * For example, multi_count_p points at osmo_gtlv_msg_session_est_req.create_pdr_count,
			 * and memb_ofs points at osmo_gtlv_msg_session_est_req.create_pdr. */
			(*multi_count_p)++;
		}
		if (presence_flag_p) {
			*presence_flag_p = true;
		}
		CHECK_SEEN(iec);
		*seen_p = true;
	}

	/* Check presence of mandatory IEs */
	for (iec = ie_coding; !osmo_gtlv_coding_end(iec); iec++) {
		if (iec->has_presence_flag)
			continue;
		multi_count_p = iec->has_count ? MEMB(obj, iec->count_ofs) : NULL;
		if (multi_count_p) {
			if (*multi_count_p < iec->count_mandatory)
				RETURN_ERROR(-EINVAL, iec->ti, "%u instances of this IE are mandatory, got %u",
					     iec->count_mandatory, *multi_count_p);
			continue;
		}
		/* Neither an optional nor a multi member, hence it must be mandatory. */
		CHECK_SEEN(iec);
		if (!*seen_p)
			RETURN_ERROR(-EINVAL, iec->ti, "Missing mandatory IE");
	}
	return 0;
}

/*! Decode a TLV structure from raw data to a decoded struct, for ordered TLV IEs.
 * How to decode IE values and where to place them in the decoded struct, is defined by ie_coding, an array terminated
 * by a '{}' entry.
 * The IEs in the TLV structure must appear in the same order as they are defined in ie_coding.
 * cause the last read TLV to overwrite all previous decodings, all into the first occurrence in ie_coding.
 * \param[out] decoded_struct  Pointer to the struct to write parsed IE data to.
 * \param[in] obj_ofs  Pass as zero. Used for nested IEs: offset added to decoded_struct to get to a sub-struct.
 * \param[in] gtlv  TLV data to parse, as given in gtlv->msg.*. Must be ready for osmo_gtlv_load_start().
 * \param[in] ie_coding  A list of permitted/expected IEI tags and instructions for decoding.
 * \param[in] err_cb  Function to call to report an error message, or NULL.
 * \param[in] err_cb_data  Caller supplied context to pass to the err_cb as 'data' argument.
 * \param[in] iei_strs  value_string array to give IEI names in error messages passed to err_cb(), or NULL.
 * \return 0 on success, negative on error.
 */
static int osmo_gtlvs_decode_ordered(void *decoded_struct, unsigned int obj_ofs, struct osmo_gtlv_load *gtlv,
				    const struct osmo_gtlv_coding *ie_coding,
				    osmo_gtlv_err_cb err_cb, void *err_cb_data, const struct value_string *iei_strs)
{
	void *obj = MEMB(decoded_struct, obj_ofs);

	osmo_gtlv_load_start(gtlv);

	for (; !osmo_gtlv_coding_end(ie_coding); ie_coding++) {
		int rc;
		bool *presence_flag = ie_coding->has_presence_flag ? MEMB(obj, ie_coding->presence_flag_ofs) : NULL;
		unsigned int *multi_count = ie_coding->has_count ? MEMB(obj, ie_coding->count_ofs) : NULL;
		struct osmo_gtlv_tag_inst peek_ti;

		rc = osmo_gtlv_load_next_by_tag_inst(gtlv, &ie_coding->ti);
		switch (rc) {
		case 0:
			break;
		case -ENOENT:
			if (!presence_flag && (!multi_count || *multi_count < ie_coding->count_mandatory))
				RETURN_ERROR(rc, ie_coding->ti, "Missing mandatory IE");
			if (presence_flag)
				*presence_flag = false;
			continue;
		default:
			RETURN_ERROR(rc, ie_coding->ti, "Error in TLV structure");
		}

		for (;;) {
			/* If this is a repeated IE, decode into the correct array index memb[idx],
			 * next idx == (*multi_count) */
			unsigned int memb_next_array_idx = multi_count ? *multi_count : 0;
			unsigned int memb_ofs = ie_coding->memb_ofs + memb_next_array_idx * ie_coding->memb_array_pitch;

			if (multi_count && memb_next_array_idx >= ie_coding->count_max)
				RETURN_ERROR(-ENOTSUP, ie_coding->ti, "Only %u instances of this IE are supported per message",
					     ie_coding->count_max);

			/* Decode IE value part */
			if (ie_coding->nested_ies) {
				/* A nested IE: the value part of this TLV is in turn a TLV structure. Decode the inner
				 * IEs. */
				struct osmo_gtlv_load inner_tlv = {
					.cfg = ie_coding->nested_ies_cfg ? : gtlv->cfg,
					.src = {
						.data = gtlv->val,
						.len = gtlv->len,
					}
				};
				bool ordered;
				switch (ie_coding->nested_ies_ordered) {
				case OSMO_GTLV_NESTED_IES_ORDERING_SAME:
				case OSMO_GTLV_NESTED_IES_ORDERED:
					ordered = true;
					break;
				case OSMO_GTLV_NESTED_IES_UNORDERED:
					ordered = false;
					break;
				default:
					OSMO_ASSERT(0);
				}
				rc = osmo_gtlvs_decode(decoded_struct, obj_ofs + memb_ofs, &inner_tlv, ordered,
						      ie_coding->nested_ies, err_cb, err_cb_data, iei_strs);
				if (rc)
					RETURN_ERROR(rc, ie_coding->ti,
						     "Error while decoding TLV structure nested inside this IE");
			} else {
				/* Normal IE, decode the specific IE data. */
				if (!ie_coding->dec_func)
					RETURN_ERROR(-EIO, ie_coding->ti, "IE definition lacks a dec_func()");
				rc = ie_coding->dec_func(decoded_struct, MEMB(obj, memb_ofs), gtlv);
				if (rc)
					RETURN_ERROR(rc, ie_coding->ti, "Error while decoding this IE");
			}

			if (presence_flag)
				*presence_flag = true;

			if (!multi_count) {
				/* Not a repeated IE. */
				break;
			}

			/* A repeated IE, record that we've added one entry. This increments the foo_count value in the
			 * decoded osmo_pfcp_msg.ies.*.
			 * For example, multi_count points at osmo_pfcp_msg_session_est_req.create_pdr_count,
			 * and memb_ofs points at osmo_pfcp_msg_session_est_req.create_pdr. */
			(*multi_count)++;

			/* Does another one of these IEs follow? */
			if (osmo_gtlv_load_peek_tag(gtlv, &peek_ti)
			    || osmo_gtlv_tag_inst_cmp(&peek_ti, &gtlv->ti)) {
				/* Next tag is a different IE, end the repetition. */
				break;
			}

			/* continue, parsing the next repetition of this tag. */
			rc = osmo_gtlv_load_next(gtlv);
			if (rc)
				return rc;
		}
		/* continue parsing the next tag. */
	}
	return 0;
}

/*! Decode an entire TLV message from raw data to decoded struct.
 * How to decode IE values and where to put them in the decoded struct is defined by ie_coding, an array terminated by
 * a '{}' entry.
 * \param[out] decoded_struct  Pointer to the struct to write parsed IE data to.
 * \param[in] obj_ofs  Pass as zero. Used for nested IEs: offset added to decoded_struct to get to a sub-struct.
 * \param[in] gtlv  TLV data to parse, as given in gtlv->msg.*. Must be ready for osmo_gtlv_load_start().
 * \param[in] ie_coding  A list of permitted/expected IEI tags and instructions for decoding.
 * \param[in] err_cb  Function to call to report an error message, or NULL.
 * \param[in] err_cb_data  Caller supplied context to pass to the err_cb as 'data' argument.
 * \param[in] iei_strs  value_string array to give IEI names in error messages passed to err_cb(), or NULL.
 * \return 0 on success, negative on error.
 */
int osmo_gtlvs_decode(void *decoded_struct, unsigned int obj_ofs, struct osmo_gtlv_load *gtlv, bool tlv_ordered,
		     const struct osmo_gtlv_coding *ie_coding,
		     osmo_gtlv_err_cb err_cb, void *err_cb_data, const struct value_string *iei_strs)
{
	if (!ie_coding)
		return -ENOTSUP;
	if (tlv_ordered)
		return osmo_gtlvs_decode_ordered(decoded_struct, obj_ofs, gtlv, ie_coding, err_cb, err_cb_data, iei_strs);
	else
		return osmo_gtlvs_decode_unordered(decoded_struct, obj_ofs, gtlv, ie_coding, err_cb, err_cb_data,
						  iei_strs);
}

/*! Encode a TLV structure from decoded struct to raw data.
 * How to encode IE values and where to read them in the decoded struct is defined by ie_coding, an array terminated by
 * a '{}' entry.
 * The IEs will be encoded in the order they appear in ie_coding.
 * \param[out] gtlv  Write data using this TLV definition to gtlv->dst.
 * \param[in] decoded_struct  C struct data to encode.
 * \param[in] obj_ofs  Nesting offset, pass as 0.
 * \param[in] ie_coding  A {} terminated list of IEI tags to encode (if present) and instructions for encoding.
 * \param[in] err_cb  Function to call to report an error message, or NULL.
 * \param[in] err_cb_data  Caller supplied context to pass to the err_cb as 'data' argument.
 * \param[in] iei_strs  value_string array to give IEI names in error messages passed to err_cb(), or NULL.
 * \return 0 on success, negative on error.
 */
int osmo_gtlvs_encode(struct osmo_gtlv_put *gtlv, const void *decoded_struct, unsigned int obj_ofs,
		     const struct osmo_gtlv_coding *ie_coding,
		     osmo_gtlv_err_cb err_cb, void *err_cb_data, const struct value_string *iei_strs)
{
	void *obj = MEMB(decoded_struct, obj_ofs);

	if (!ie_coding)
		return -ENOTSUP;

	for (; !osmo_gtlv_coding_end(ie_coding); ie_coding++) {
		int rc;
		bool *presence_flag_p = ie_coding->has_presence_flag ? MEMB(obj, ie_coding->presence_flag_ofs) : NULL;
		unsigned int *multi_count_p = ie_coding->has_count ? MEMB(obj, ie_coding->count_ofs) : NULL;
		unsigned int n;
		unsigned int i;

		if (presence_flag_p && !*presence_flag_p)
			continue;

		if (multi_count_p) {
			n = *multi_count_p;
			if (!ie_coding->memb_array_pitch)
				RETURN_ERROR(-EFAULT, ie_coding->ti,
					     "Error in protocol definition: The ie_coding lacks a memb_array_pitch"
					     " value, cannot be used as multi-IE\n");
		} else {
			n = 1;
		}

		for (i = 0; i < n; i++) {
			unsigned int memb_ofs;

			osmo_gtlv_put_tli(gtlv, &ie_coding->ti, 0);

			/* If this is a repeated IE, encode from the correct array index */
			if (multi_count_p && i >= ie_coding->count_max)
				RETURN_ERROR(-ENOTSUP, ie_coding->ti,
					     "Only %u instances of this IE are supported per message", ie_coding->count_max);
			memb_ofs = ie_coding->memb_ofs + i * ie_coding->memb_array_pitch;

			if (ie_coding->nested_ies) {
				struct osmo_gtlv_put nested_tlv = {
					.cfg = ie_coding->nested_ies_cfg ? : gtlv->cfg,
					.dst = gtlv->dst,
				};
				rc = osmo_gtlvs_encode(&nested_tlv, decoded_struct, obj_ofs + memb_ofs,
						      ie_coding->nested_ies, err_cb, err_cb_data, iei_strs);
				if (rc)
					RETURN_ERROR(rc, ie_coding->ti,
						     "Error while encoding TLV structure nested inside this IE");
			} else {
				rc = ie_coding->enc_func(gtlv, decoded_struct, MEMB(obj, memb_ofs));
				if (rc)
					RETURN_ERROR(rc, ie_coding->ti, "Error while encoding this IE");
			}

			osmo_gtlv_put_update_tl(gtlv);
		}
	}
	return 0;
}

/*! Compose a human readable string describing a decoded struct.
 * How to encode IE values and where to read them in the decoded struct is defined by ie_coding, an array terminated by
 * a '{}' entry.
 * The IEs will be encoded in the order they appear in ie_coding.
 * \param[out] buf  Return the string in this buffer.
 * \param[in] buflen  Size of buf.
 * \param[in] decoded_struct  C struct data to encode.
 * \param[in] obj_ofs  Nesting offset, pass as 0.
 * \param[in] ie_coding  A {} terminated list of IEI tags to encode (if present) and instructions for encoding.
 * \param[in] iei_strs  value_string array to give IEI names in tag headers, or NULL.
 * \return number of characters that would be written if the buffer is large enough, like snprintf().
 */
int osmo_gtlvs_encode_to_str_buf(char *buf, size_t buflen, const void *decoded_struct, unsigned int obj_ofs,
				const struct osmo_gtlv_coding *ie_coding, const struct value_string *iei_strs)
{
	struct osmo_strbuf sb = { .buf = buf, .len = buflen };

	void *obj = MEMB(decoded_struct, obj_ofs);

	if (!ie_coding)
		return -ENOTSUP;

	for (; !osmo_gtlv_coding_end(ie_coding); ie_coding++) {
		bool *presence_flag_p = ie_coding->has_presence_flag ? MEMB(obj, ie_coding->presence_flag_ofs) : NULL;
		unsigned int *multi_count_p = ie_coding->has_count ? MEMB(obj, ie_coding->count_ofs) : NULL;
		unsigned int n;
		unsigned int i;

		if (presence_flag_p && !*presence_flag_p)
			continue;

		if (multi_count_p) {
			n = *multi_count_p;
		} else {
			n = 1;
		}

		if (!n)
			continue;

		OSMO_STRBUF_PRINTF(sb, " '%s'=", get_value_string(iei_strs, ie_coding->ti.tag));
		if (multi_count_p)
			OSMO_STRBUF_PRINTF(sb, "{ ");

		for (i = 0; i < n; i++) {
			unsigned int memb_ofs;

			/* If this is a repeated IE, encode from the correct array index */
			if (multi_count_p && i >= ie_coding->count_max)
				return -ENOTSUP;
			if (i > 0)
				OSMO_STRBUF_PRINTF(sb, ", ");

			memb_ofs = ie_coding->memb_ofs + i * ie_coding->memb_array_pitch;

			if (ie_coding->nested_ies) {
				OSMO_STRBUF_PRINTF(sb, "{");
				OSMO_STRBUF_APPEND(sb, osmo_gtlvs_encode_to_str_buf, decoded_struct, obj_ofs + memb_ofs,
						   ie_coding->nested_ies, iei_strs);
				OSMO_STRBUF_PRINTF(sb, " }");
			} else {
				if (ie_coding->enc_to_str_func)
					OSMO_STRBUF_APPEND(sb, ie_coding->enc_to_str_func, MEMB(obj, memb_ofs));
				else
					OSMO_STRBUF_PRINTF(sb, "(enc_to_str_func==NULL)");
			}
		}

		if (multi_count_p)
			OSMO_STRBUF_PRINTF(sb, " }");
	}
	return sb.chars_needed;
}

/*! Compose a human readable string describing a decoded struct.
 * Like osmo_gtlvs_encode_to_str_buf() but returns a talloc allocated string.
 * \param[in] ctx  talloc context to allocate from, e.g. OTC_SELECT.
 * \param[in] decoded_struct  C struct data to encode.
 * \param[in] obj_ofs  Nesting offset, pass as 0.
 * \param[in] ie_coding  A {} terminated list of IEI tags to encode (if present) and instructions for encoding.
 * \param[in] iei_strs  value_string array to give IEI names in tag headers, or NULL.
 * \return human readable string.
 */
char *osmo_gtlvs_encode_to_str_c(void *ctx, const void *decoded_struct, unsigned int obj_ofs,
				const struct osmo_gtlv_coding *ie_coding, const struct value_string *iei_strs)
{
	OSMO_NAME_C_IMPL(ctx, 256, "ERROR", osmo_gtlvs_encode_to_str_buf, decoded_struct, obj_ofs, ie_coding, iei_strs)
}
