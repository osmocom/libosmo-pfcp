/* Decoded PFCP IEs, to be used by the auto-generated pfcp_ies_auto.c. */
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

#include <osmocom/core/socket.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/msgb.h>

#include <osmocom/gtlv/gtlv.h>

#include <osmocom/pfcp/pfcp_ies_custom.h>
#include <osmocom/pfcp/pfcp_strs.h>
#include <osmocom/pfcp/pfcp_msg.h>

/* Assumes presence of local variable osmo_pfcp_msg *m. m->log_ctx may be NULL. */
#define RETURN_ERROR(RC, FMT, ARGS...) \
	do {\
		OSMO_ASSERT(decoded_struct); \
		OSMO_LOG_PFCP_MSG(OSMO_PFCP_MSG_FOR_IES(decoded_struct), LOGL_ERROR, FMT " (%d: %s)\n", ##ARGS, RC, \
				  strerror((RC) > 0 ? (RC) : -(RC))); \
		return RC; \
	} while (0)

/* Assumes presence of local variable osmo_gtlv_load *tlv. Usage:
 *   ENSURE_LENGTH_IS_EXACTLY(2);
 */
#define ENSURE_LENGTH_IS_EXACTLY(VAL) \
	do { \
		if (!(tlv->len == VAL)) \
			RETURN_ERROR(-EINVAL, "IE has length = %zu, expected length == " #VAL, tlv->len); \
	} while (0)

/* Assumes presence of local variable osmo_gtlv_load *tlv. Usage:
 *   ENSURE_LENGTH_IS_AT_LEAST(1);
 */
#define ENSURE_LENGTH_IS_AT_LEAST(VAL) \
	do { \
		if (!(tlv->len >= VAL)) \
			RETURN_ERROR(-EINVAL, "IE has length = %zu, expected length >= " #VAL, tlv->len); \
	} while (0)

/* Assumes presence of local variable osmo_gtlv_load *tlv. Usage:
 *   const uint8_t *pos = tlv->val;
 *   ENSURE_REMAINING_LENGTH_IS_AT_LEAST("first part", pos, 23);
 *   <parse first part>
 *   pos += 23;
 *   ENSURE_REMAINING_LENGTH_IS_AT_LEAST("very long part", pos, 235);
 *   <parse very long part>
 *   pos += 235;
 */
#define ENSURE_REMAINING_LENGTH_IS_AT_LEAST(NAME, POS, MIN_VAL) \
	do { \
		if (!((tlv->len - ((POS) - tlv->val)) >= MIN_VAL)) \
			RETURN_ERROR(-EINVAL, \
				     "at value octet %d: %zu octets remaining, but " #NAME " requires length >= " #MIN_VAL, \
				     (int)((POS) - tlv->val), \
				     tlv->len - ((POS) - tlv->val)); \
	} while (0)

void osmo_pfcp_ie_f_seid_set(struct osmo_pfcp_ie_f_seid *f_seid, uint64_t seid, const struct osmo_sockaddr *remote_addr)
{
	*f_seid = (struct osmo_pfcp_ie_f_seid) {
		.seid = seid,
	};
	osmo_pfcp_ip_addrs_set(&f_seid->ip_addr, remote_addr);
}

int osmo_pfcp_dec_cause(void *decoded_struct, void *decode_to, const struct osmo_gtlv_load *tlv)
{
	enum osmo_pfcp_cause *cause = decode_to;
	ENSURE_LENGTH_IS_EXACTLY(1);
	*cause = *tlv->val;
	return 0;
}

int osmo_pfcp_enc_cause(struct osmo_gtlv_put *tlv, const void *decoded_struct, const void *encode_from)
{
	const enum osmo_pfcp_cause *cause = encode_from;
	msgb_put_u8(tlv->dst, *cause);
	return 0;
}

int osmo_pfcp_enc_to_str_cause(char *buf, size_t buflen, const void *encode_from)
{
	const enum osmo_pfcp_cause *cause = encode_from;
	return snprintf(buf, buflen, "%s", osmo_pfcp_cause_str(*cause));
}

int osmo_pfcp_dec_offending_ie(void *decoded_struct, void *decode_to, const struct osmo_gtlv_load *tlv)
{
	enum osmo_pfcp_iei *offending_ie = decode_to;
	ENSURE_LENGTH_IS_EXACTLY(2);
	*offending_ie = osmo_load16be(tlv->val);
	return 0;
}

int osmo_pfcp_enc_offending_ie(struct osmo_gtlv_put *tlv, const void *decoded_struct, const void *encode_from)
{
	const enum osmo_pfcp_iei *offending_ie = encode_from;
	msgb_put_u16(tlv->dst, *offending_ie);
	return 0;
}

int osmo_pfcp_enc_to_str_offending_ie(char *buf, size_t buflen, const void *encode_from)
{
	const enum osmo_pfcp_iei *offending_ie = encode_from;
	return snprintf(buf, buflen, "%s", osmo_pfcp_iei_str(*offending_ie));
}

int osmo_pfcp_dec_8(void *decoded_struct, void *decode_to, const struct osmo_gtlv_load *tlv)
{
	uint8_t *u8 = decode_to;
	ENSURE_LENGTH_IS_AT_LEAST(1);
	*u8 = tlv->val[0];
	return 0;
}

int osmo_pfcp_enc_8(struct osmo_gtlv_put *tlv, const void *decoded_struct, const void *encode_from)
{
	const uint8_t *u8 = encode_from;
	msgb_put_u8(tlv->dst, *u8);
	return 0;
}

int osmo_pfcp_enc_to_str_8(char *buf, size_t buflen, const void *encode_from)
{
	const uint8_t *u8 = encode_from;
	return snprintf(buf, buflen, "%u", *u8);
}

int osmo_pfcp_dec_16be(void *decoded_struct, void *decode_to, const struct osmo_gtlv_load *tlv)
{
	uint16_t *u16 = decode_to;
	ENSURE_LENGTH_IS_AT_LEAST(2);
	*u16 = osmo_load16be(tlv->val);
	return 0;
}

int osmo_pfcp_enc_16be(struct osmo_gtlv_put *tlv, const void *decoded_struct, const void *encode_from)
{
	const uint16_t *u16 = encode_from;
	msgb_put_u16(tlv->dst, *u16);
	return 0;
}

int osmo_pfcp_enc_to_str_16be(char *buf, size_t buflen, const void *encode_from)
{
	const uint16_t *u16 = encode_from;
	return snprintf(buf, buflen, "%u", *u16);
}

int osmo_pfcp_dec_32be(void *decoded_struct, void *decode_to, const struct osmo_gtlv_load *tlv)
{
	uint32_t *u32 = decode_to;
	ENSURE_LENGTH_IS_AT_LEAST(4);
	*u32 = osmo_load32be(tlv->val);
	return 0;
}

int osmo_pfcp_enc_32be(struct osmo_gtlv_put *tlv, const void *decoded_struct, const void *encode_from)
{
	const uint32_t *u32 = encode_from;
	msgb_put_u32(tlv->dst, *u32);
	return 0;
}

int osmo_pfcp_enc_to_str_32be(char *buf, size_t buflen, const void *encode_from)
{
	const uint32_t *u32 = encode_from;
	return snprintf(buf, buflen, "%u", *u32);
}

int osmo_pfcp_dec_3gpp_iface_type(void *decoded_struct, void *decode_to, const struct osmo_gtlv_load *tlv)
{
	enum osmo_pfcp_3gpp_iface_type *_3gpp_iface_type = decode_to;
	ENSURE_LENGTH_IS_AT_LEAST(1);
	*_3gpp_iface_type = tlv->val[0] & 0x3f;
	return 0;
}

int osmo_pfcp_enc_3gpp_iface_type(struct osmo_gtlv_put *tlv, const void *decoded_struct, const void *encode_from)
{
	const enum osmo_pfcp_3gpp_iface_type *_3gpp_iface_type = encode_from;
	msgb_put_u8(tlv->dst, (uint8_t)(*_3gpp_iface_type) & 0x3f);
	return 0;
}

int osmo_pfcp_enc_to_str_3gpp_iface_type(char *buf, size_t buflen, const void *encode_from)
{
	const enum osmo_pfcp_3gpp_iface_type *_3gpp_iface_type = encode_from;
	return snprintf(buf, buflen, "%s", osmo_pfcp_3gpp_iface_type_str(*_3gpp_iface_type));
}

int osmo_pfcp_dec_source_iface(void *decoded_struct, void *decode_to, const struct osmo_gtlv_load *tlv)
{
	enum osmo_pfcp_source_iface *source_iface = decode_to;
	ENSURE_LENGTH_IS_AT_LEAST(1);
	*source_iface = tlv->val[0] & 0xf;
	return 0;
}

int osmo_pfcp_enc_source_iface(struct osmo_gtlv_put *tlv, const void *decoded_struct, const void *encode_from)
{
	const enum osmo_pfcp_source_iface *source_iface = encode_from;
	msgb_put_u8(tlv->dst, (uint8_t)(*source_iface) & 0xf);
	return 0;
}

int osmo_pfcp_enc_to_str_source_iface(char *buf, size_t buflen, const void *encode_from)
{
	const enum osmo_pfcp_source_iface *source_iface = encode_from;
	return snprintf(buf, buflen, "%s", osmo_pfcp_source_iface_str(*source_iface));
}

int osmo_pfcp_dec_dest_iface(void *decoded_struct, void *decode_to, const struct osmo_gtlv_load *tlv)
{
	enum osmo_pfcp_dest_iface *dest_interface = decode_to;
	ENSURE_LENGTH_IS_AT_LEAST(1);
	*dest_interface = tlv->val[0] & 0xf;
	return 0;
}

int osmo_pfcp_enc_dest_iface(struct osmo_gtlv_put *tlv, const void *decoded_struct, const void *encode_from)
{
	const enum osmo_pfcp_dest_iface *dest_interface = encode_from;
	msgb_put_u8(tlv->dst, (uint8_t)(*dest_interface) & 0xf);
	return 0;
}

int osmo_pfcp_enc_to_str_dest_iface(char *buf, size_t buflen, const void *encode_from)
{
	const enum osmo_pfcp_dest_iface *dest_iface = encode_from;
	return snprintf(buf, buflen, "%s", osmo_pfcp_dest_iface_str(*dest_iface));
}

int osmo_pfcp_dec_node_id(void *decoded_struct, void *decode_to, const struct osmo_gtlv_load *tlv)
{
	struct osmo_pfcp_ie_node_id *node_id = decode_to;
	const void *ip;
	unsigned int ip_len;
	unsigned int want_len;
	ENSURE_LENGTH_IS_AT_LEAST(1);
	node_id->type = *(uint8_t *)tlv->val;
	ip = &tlv->val[1];
	ip_len = tlv->len - 1;

	switch (node_id->type) {
	case OSMO_PFCP_NODE_ID_T_IPV4:
		want_len = sizeof(node_id->ip.u.sin.sin_addr);
		if (ip_len != want_len)
			RETURN_ERROR(-EINVAL, "Node ID: wrong IPv4 address value length %u, expected %u",
				     ip_len, want_len);
		osmo_sockaddr_from_octets(&node_id->ip, ip, ip_len);
		break;
	case OSMO_PFCP_NODE_ID_T_IPV6:
		want_len = sizeof(node_id->ip.u.sin6.sin6_addr);
		if (ip_len != want_len)
			RETURN_ERROR(-EINVAL, "Node ID: wrong IPv6 address value length %u, expected %u",
				     ip_len, want_len);
		osmo_sockaddr_from_octets(&node_id->ip, ip, ip_len);
		break;
	case OSMO_PFCP_NODE_ID_T_FQDN:
		/* Copy and add a trailing nul */
		OSMO_STRLCPY_ARRAY(node_id->fqdn, ip);
		break;
	default:
		RETURN_ERROR(-EINVAL, "Invalid Node ID Type: %d", node_id->type);
	}
	return 0;
}

int osmo_pfcp_enc_node_id(struct osmo_gtlv_put *tlv, const void *decoded_struct, const void *encode_from)
{
	unsigned int l;
	const struct osmo_pfcp_ie_node_id *node_id = encode_from;
	msgb_put_u8(tlv->dst, node_id->type);
	switch (node_id->type) {
	case OSMO_PFCP_NODE_ID_T_IPV4:
		l = sizeof(node_id->ip.u.sin.sin_addr);
		osmo_sockaddr_to_octets(msgb_put(tlv->dst, l), l, &node_id->ip);
		break;
	case OSMO_PFCP_NODE_ID_T_IPV6:
		l = sizeof(node_id->ip.u.sin6.sin6_addr);
		osmo_sockaddr_to_octets(msgb_put(tlv->dst, l), l, &node_id->ip);
		break;
	case OSMO_PFCP_NODE_ID_T_FQDN:
		l = strnlen(node_id->fqdn, sizeof(node_id->fqdn));
		/* Copy without trailing nul */
		memcpy((char *)msgb_put(tlv->dst, l), node_id->fqdn, l);
		break;
	default:
		RETURN_ERROR(-EINVAL, "Invalid Node ID Type: %d", node_id->type);
	}
	return 0;
}

int osmo_pfcp_ie_node_id_to_str_buf(char *buf, size_t buflen, const struct osmo_pfcp_ie_node_id *node_id)
{
	struct osmo_strbuf sb = { .buf = buf, .len = buflen };

	switch (node_id->type) {
	case OSMO_PFCP_NODE_ID_T_IPV4:
		OSMO_STRBUF_PRINTF(sb, "v4:");
		break;
	case OSMO_PFCP_NODE_ID_T_IPV6:
		OSMO_STRBUF_PRINTF(sb, "v6:");
		break;
	case OSMO_PFCP_NODE_ID_T_FQDN:
		OSMO_STRBUF_PRINTF(sb, "fqdn:");
		OSMO_STRBUF_APPEND(sb, osmo_quote_str_buf3,
				   node_id->fqdn, strnlen(node_id->fqdn, sizeof(node_id->fqdn)));
		return sb.chars_needed;
	default:
		OSMO_STRBUF_PRINTF(sb, "unknown-node-id-type-%u", node_id->type);
		return sb.chars_needed;
	}

	OSMO_STRBUF_APPEND(sb, osmo_sockaddr_to_str_buf2, &node_id->ip);
	return sb.chars_needed;
}

char *osmo_pfcp_ie_node_id_to_str_c(void *ctx, const struct osmo_pfcp_ie_node_id *node_id)
{
	OSMO_NAME_C_IMPL(ctx, 64, "ERROR", osmo_pfcp_ie_node_id_to_str_buf, node_id)
}

int osmo_pfcp_enc_to_str_node_id(char *buf, size_t buflen, const void *encode_from)
{
	return osmo_pfcp_ie_node_id_to_str_buf(buf, buflen, encode_from);
}

bool osmo_pfcp_bits_get(const uint8_t *bits, unsigned int bitpos)
{
	unsigned int bytenum = bitpos / 8;
	unsigned int bitmask = 1 << (bitpos % 8);

	return (bool)(bits[bytenum] & bitmask);
}

void osmo_pfcp_bits_set(uint8_t *bits, unsigned int bitpos, bool val)
{
	unsigned int bytenum = bitpos / 8;
	unsigned int bitmask = 1 << (bitpos % 8);

	if (val)
		bits[bytenum] |= bitmask;
	else
		bits[bytenum] &= ~bitmask;
}

int osmo_pfcp_bits_to_str_buf(char *buf, size_t buflen, const uint8_t *bits, const struct value_string *bit_strs)
{
	struct osmo_strbuf sb = { .buf = buf, .len = buflen };
	OSMO_STRBUF_PRINTF(sb, "(");
	for (; bit_strs->str; bit_strs++) {
		if (osmo_pfcp_bits_get(bits, bit_strs->value)) {
			OSMO_STRBUF_PRINTF(sb, " %s", bit_strs->str);
		}
	}
	OSMO_STRBUF_PRINTF(sb, " )");
	return sb.chars_needed;
}

char *osmo_pfcp_bits_to_str_c(void *ctx, const uint8_t *bits, const struct value_string *bit_str)
{
	OSMO_NAME_C_IMPL(ctx, 64, "ERROR", osmo_pfcp_bits_to_str_buf, bits, bit_str)
}

int osmo_pfcp_dec_up_function_features(void *decoded_struct, void *decode_to, const struct osmo_gtlv_load *tlv)
{
	struct osmo_pfcp_ie_up_function_features *up_function_features = decode_to;
	ENSURE_LENGTH_IS_AT_LEAST(6);
	memcpy(up_function_features->bits, tlv->val, 6);
	return 0;
}

int osmo_pfcp_enc_up_function_features(struct osmo_gtlv_put *tlv, const void *decoded_struct, const void *encode_from)
{
	const struct osmo_pfcp_ie_up_function_features *up_function_features = encode_from;
	memcpy(msgb_put(tlv->dst, 6), up_function_features->bits, 6);
	return 0;
}

int osmo_pfcp_enc_to_str_up_function_features(char *buf, size_t buflen, const void *encode_from)
{
	const struct osmo_pfcp_ie_up_function_features *up_function_features = encode_from;
	return osmo_pfcp_bits_to_str_buf(buf, buflen, up_function_features->bits, osmo_pfcp_up_feature_strs);
}

int osmo_pfcp_dec_cp_function_features(void *decoded_struct, void *decode_to, const struct osmo_gtlv_load *tlv)
{
	struct osmo_pfcp_ie_cp_function_features *cp_function_features = decode_to;
	ENSURE_LENGTH_IS_AT_LEAST(sizeof(cp_function_features->bits));
	memcpy(cp_function_features->bits, tlv->val, sizeof(cp_function_features->bits));
	return 0;
}

int osmo_pfcp_enc_cp_function_features(struct osmo_gtlv_put *tlv, const void *decoded_struct, const void *encode_from)
{
	const struct osmo_pfcp_ie_cp_function_features *cp_function_features = encode_from;
	memcpy(msgb_put(tlv->dst, sizeof(cp_function_features->bits)),
	       cp_function_features->bits, sizeof(cp_function_features->bits));
	return 0;
}

int osmo_pfcp_enc_to_str_cp_function_features(char *buf, size_t buflen, const void *encode_from)
{
	const struct osmo_pfcp_ie_cp_function_features *cp_function_features = encode_from;
	return osmo_pfcp_bits_to_str_buf(buf, buflen, cp_function_features->bits, osmo_pfcp_cp_feature_strs);
}

int osmo_pfcp_dec_f_seid(void *decoded_struct, void *decode_to, const struct osmo_gtlv_load *tlv)
{
	struct osmo_pfcp_ie_f_seid *f_seid = decode_to;
	uint8_t flags;
	uint8_t pos;
	unsigned int l;
	/* flags and 8 octet seid */
	ENSURE_LENGTH_IS_AT_LEAST(9);
	flags = tlv->val[0];
	f_seid->ip_addr.v6_present = flags & 1;
	f_seid->ip_addr.v4_present = flags & 2;
	f_seid->seid = osmo_load64be(&tlv->val[1]);
	pos = 9;
	if (f_seid->ip_addr.v4_present) {
		l = sizeof(f_seid->ip_addr.v4.u.sin.sin_addr);
		if (pos + l > tlv->len)
			RETURN_ERROR(-EINVAL, "F-SEID IE is too short for the IPv4 address: %zu", tlv->len);
		osmo_sockaddr_from_octets(&f_seid->ip_addr.v4, &tlv->val[pos], l);
		pos += l;
	}
	if (f_seid->ip_addr.v6_present) {
		l = sizeof(f_seid->ip_addr.v4.u.sin6.sin6_addr);
		if (pos + l > tlv->len)
			RETURN_ERROR(-EINVAL, "F-SEID IE is too short for the IPv6 address: %zu", tlv->len);
		osmo_sockaddr_from_octets(&f_seid->ip_addr.v6, &tlv->val[pos], l);
		pos += l;
	}
	return 0;
}

int osmo_pfcp_enc_f_seid(struct osmo_gtlv_put *tlv, const void *decoded_struct, const void *encode_from)
{
	const struct osmo_pfcp_ie_f_seid *f_seid = encode_from;
	unsigned int l;
	uint8_t flags = (f_seid->ip_addr.v6_present ? 1 : 0) + (f_seid->ip_addr.v4_present ? 2 : 0);
	/* flags and 8 octet seid */
	msgb_put_u8(tlv->dst, flags);
	osmo_store64be(f_seid->seid, msgb_put(tlv->dst, 8));

	if (f_seid->ip_addr.v4_present) {
		if (f_seid->ip_addr.v4.u.sin.sin_family != AF_INET)
			RETURN_ERROR(-EINVAL,
				     "f_seid IE indicates IPv4 address, but there is no ipv4_addr");
		l = sizeof(f_seid->ip_addr.v4.u.sin.sin_addr);
		osmo_sockaddr_to_octets(msgb_put(tlv->dst, l), l, &f_seid->ip_addr.v4);
	}
	if (f_seid->ip_addr.v6_present) {
		if (f_seid->ip_addr.v6.u.sin6.sin6_family != AF_INET6)
			RETURN_ERROR(-EINVAL,
				     "f_seid IE indicates IPv6 address, but there is no ipv6_addr");
		l = sizeof(f_seid->ip_addr.v6.u.sin6.sin6_addr);
		osmo_sockaddr_to_octets(msgb_put(tlv->dst, l), l, &f_seid->ip_addr.v6);
	}
	return 0;
}

static int ip_addrs_to_str_buf(char *buf, size_t buflen, const struct osmo_pfcp_ip_addrs *addrs)
{
	struct osmo_strbuf sb = { .buf = buf, .len = buflen };
	if (addrs->v4_present) {
		OSMO_STRBUF_PRINTF(sb, ",v4:");
		OSMO_STRBUF_APPEND(sb, osmo_sockaddr_to_str_buf2, &addrs->v4);
	}
	if (addrs->v6_present) {
		OSMO_STRBUF_PRINTF(sb, ",v6:");
		OSMO_STRBUF_APPEND(sb, osmo_sockaddr_to_str_buf2, &addrs->v6);
	}
	return sb.chars_needed;
}

int osmo_pfcp_enc_to_str_f_seid(char *buf, size_t buflen, const void *encode_from)
{
	const struct osmo_pfcp_ie_f_seid *f_seid = encode_from;
	struct osmo_strbuf sb = { .buf = buf, .len = buflen };
	OSMO_STRBUF_PRINTF(sb, "0x%"PRIx64, f_seid->seid);
	OSMO_STRBUF_APPEND(sb, ip_addrs_to_str_buf, &f_seid->ip_addr);
	return sb.chars_needed;
}

int osmo_pfcp_dec_f_teid(void *decoded_struct, void *decode_to, const struct osmo_gtlv_load *tlv)
{
	struct osmo_pfcp_ie_f_teid *f_teid = decode_to;
	uint8_t flags;
	const uint8_t *pos;

	*f_teid = (struct osmo_pfcp_ie_f_teid){};

	pos = tlv->val;

	ENSURE_REMAINING_LENGTH_IS_AT_LEAST("flags", pos, 1);
	flags = *pos;
	pos++;
	f_teid->choose_flag = flags & 4;

	if (!f_teid->choose_flag) {
		/* A fixed TEID and address are provided */
		f_teid->fixed.ip_addr.v4_present = flags & 1;
		f_teid->fixed.ip_addr.v6_present = flags & 2;

		ENSURE_REMAINING_LENGTH_IS_AT_LEAST("TEID", pos, 4);
		f_teid->fixed.teid = osmo_load32be(pos);
		pos += 4;

		if (f_teid->fixed.ip_addr.v4_present) {
			osmo_static_assert(sizeof(f_teid->fixed.ip_addr.v4.u.sin.sin_addr) == 4, sin_addr_size_is_4);
			ENSURE_REMAINING_LENGTH_IS_AT_LEAST("IPv4 address", pos, 4);
			osmo_sockaddr_from_octets(&f_teid->fixed.ip_addr.v4, pos, 4);
			pos += 4;
		}
		if (f_teid->fixed.ip_addr.v6_present) {
			osmo_static_assert(sizeof(f_teid->fixed.ip_addr.v6.u.sin6.sin6_addr) == 16, sin6_addr_size_is_16);
			ENSURE_REMAINING_LENGTH_IS_AT_LEAST("IPv6 address", pos, 16);
			osmo_sockaddr_from_octets(&f_teid->fixed.ip_addr.v6, pos, 16);
			pos += 16;
		}
	} else {
		/* CH flag is 1, choose an F-TEID. */
		f_teid->choose.ipv4_addr = flags & 1;
		f_teid->choose.ipv6_addr = flags & 2;
		f_teid->choose.choose_id_present = flags & 8;

		if (f_teid->choose.choose_id_present) {
			ENSURE_REMAINING_LENGTH_IS_AT_LEAST("CHOOSE ID", pos, 1);
			f_teid->choose.choose_id = *pos;
			pos++;
		}
	}
	return 0;
}

int osmo_pfcp_enc_f_teid(struct osmo_gtlv_put *tlv, const void *decoded_struct, const void *encode_from)
{
	const struct osmo_pfcp_ie_f_teid *f_teid = encode_from;
	uint8_t flags;

	flags = (f_teid->choose_flag ? 4 : 0);

	if (!f_teid->choose_flag) {
		/* A fixed TEID and address are provided */
		flags |= (f_teid->fixed.ip_addr.v4_present ? 1 : 0)
			 + (f_teid->fixed.ip_addr.v6_present ? 2 : 0);

		msgb_put_u8(tlv->dst, flags);
		msgb_put_u32(tlv->dst, f_teid->fixed.teid);

		if (f_teid->fixed.ip_addr.v4_present) {
			if (f_teid->fixed.ip_addr.v4.u.sin.sin_family != AF_INET)
				RETURN_ERROR(-EINVAL,
					     "f_teid IE indicates IPv4 address, but there is no ipv4_addr"
					     " (sin_family = %d != AF_INET)", f_teid->fixed.ip_addr.v4.u.sin.sin_family);
			osmo_sockaddr_to_octets(msgb_put(tlv->dst, 4), 4, &f_teid->fixed.ip_addr.v4);
		}
		if (f_teid->fixed.ip_addr.v6_present) {
			if (f_teid->fixed.ip_addr.v6.u.sin6.sin6_family != AF_INET6)
				RETURN_ERROR(-EINVAL,
					     "f_teid IE indicates IPv6 address, but there is no ipv6_addr"
					     " (sin6_family = %d != AF_INET6)", f_teid->fixed.ip_addr.v6.u.sin6.sin6_family);
			osmo_sockaddr_to_octets(msgb_put(tlv->dst, 16), 16, &f_teid->fixed.ip_addr.v6);
		}
	} else {
		flags |= (f_teid->choose.ipv4_addr ? 1 : 0)
			 + (f_teid->choose.ipv6_addr ? 2 : 0)
			 + (f_teid->choose.choose_id_present ? 8 : 0);
		msgb_put_u8(tlv->dst, flags);
		if (f_teid->choose.choose_id_present)
			msgb_put_u8(tlv->dst, f_teid->choose.choose_id);
	}
	return 0;
}

int osmo_pfcp_ie_f_teid_to_str_buf(char *buf, size_t buflen, const struct osmo_pfcp_ie_f_teid *ft)
{
	struct osmo_strbuf sb = { .buf = buf, .len = buflen };
	if (ft->choose_flag) {
		OSMO_STRBUF_PRINTF(sb, "CHOOSE");
		if (ft->choose.ipv4_addr)
			OSMO_STRBUF_PRINTF(sb, "-v4");
		if (ft->choose.ipv6_addr)
			OSMO_STRBUF_PRINTF(sb, "-v6");
		if (ft->choose.choose_id_present)
			OSMO_STRBUF_PRINTF(sb, "-id%u", ft->choose.choose_id);
	} else {
		OSMO_STRBUF_PRINTF(sb, "TEID-0x%x", ft->fixed.teid);
		OSMO_STRBUF_APPEND(sb, ip_addrs_to_str_buf, &ft->fixed.ip_addr);
	}
	return sb.chars_needed;
}

char *osmo_pfcp_ie_f_teid_to_str_c(void *ctx, const struct osmo_pfcp_ie_f_teid *ft)
{
	OSMO_NAME_C_IMPL(ctx, 64, "ERROR", osmo_pfcp_ie_f_teid_to_str_buf, ft)
}

int osmo_pfcp_enc_to_str_f_teid(char *buf, size_t buflen, const void *encode_from)
{
	const struct osmo_pfcp_ie_f_teid *f_teid = encode_from;
	return osmo_pfcp_ie_f_teid_to_str_buf(buf, buflen, f_teid);
}

int osmo_pfcp_dec_apply_action(void *decoded_struct, void *decode_to, const struct osmo_gtlv_load *tlv)
{
	struct osmo_pfcp_ie_apply_action *apply_action = decode_to;
	ENSURE_LENGTH_IS_AT_LEAST(1);
	*apply_action = (struct osmo_pfcp_ie_apply_action){};
	memcpy(apply_action->bits, tlv->val, OSMO_MIN(tlv->len, sizeof(apply_action->bits)));
	return 0;
}

int osmo_pfcp_enc_apply_action(struct osmo_gtlv_put *tlv, const void *decoded_struct, const void *encode_from)
{
	const struct osmo_pfcp_ie_apply_action *apply_action = encode_from;
	memcpy(msgb_put(tlv->dst, sizeof(apply_action->bits)),
	       apply_action->bits, sizeof(apply_action->bits));
	return 0;
}

int osmo_pfcp_enc_to_str_apply_action(char *buf, size_t buflen, const void *encode_from)
{
	const struct osmo_pfcp_ie_apply_action *apply_action = encode_from;
	return osmo_pfcp_bits_to_str_buf(buf, buflen, apply_action->bits, osmo_pfcp_apply_action_strs);
}

int osmo_pfcp_dec_network_inst(void *decoded_struct, void *decode_to, const struct osmo_gtlv_load *tlv)
{
	struct osmo_pfcp_ie_network_inst *network_inst = decode_to;
	osmo_strlcpy(network_inst->str, (const char *)tlv->val, OSMO_MIN(sizeof(network_inst->str), tlv->len+1));
	return 0;
}

int osmo_pfcp_enc_network_inst(struct osmo_gtlv_put *tlv, const void *decoded_struct, const void *encode_from)
{
	const struct osmo_pfcp_ie_network_inst *network_inst = encode_from;
	unsigned int l = strlen(network_inst->str);
	if (l)
		memcpy(msgb_put(tlv->dst, l), network_inst->str, l);
	return 0;
}

int osmo_pfcp_enc_to_str_network_inst(char *buf, size_t buflen, const void *encode_from)
{
	const struct osmo_pfcp_ie_network_inst *network_inst = encode_from;
	return osmo_quote_str_buf3(buf, buflen, network_inst->str,
				   strnlen(network_inst->str, sizeof(network_inst->str)));
}

int osmo_pfcp_dec_outer_header_creation(void *decoded_struct, void *decode_to, const struct osmo_gtlv_load *tlv)
{
	struct osmo_pfcp_ie_outer_header_creation *ohc = decode_to;
	const uint8_t *pos;
	bool gtp_u_udp_ipv4;
	bool gtp_u_udp_ipv6;
	bool udp_ipv4;
	bool udp_ipv6;
	bool ipv4;
	bool ipv6;
	bool c_tag;
	bool s_tag;

	*ohc = (struct osmo_pfcp_ie_outer_header_creation){};

	ENSURE_LENGTH_IS_AT_LEAST(2);

	memcpy(ohc->desc_bits, tlv->val, 2);

	gtp_u_udp_ipv4 = osmo_pfcp_bits_get(ohc->desc_bits, OSMO_PFCP_OUTER_HEADER_CREATION_GTP_U_UDP_IPV4);
	udp_ipv4 = osmo_pfcp_bits_get(ohc->desc_bits, OSMO_PFCP_OUTER_HEADER_CREATION_UDP_IPV4);
	ipv4 = osmo_pfcp_bits_get(ohc->desc_bits, OSMO_PFCP_OUTER_HEADER_CREATION_IPV4);
	gtp_u_udp_ipv6 = osmo_pfcp_bits_get(ohc->desc_bits, OSMO_PFCP_OUTER_HEADER_CREATION_GTP_U_UDP_IPV6);
	udp_ipv6 = osmo_pfcp_bits_get(ohc->desc_bits, OSMO_PFCP_OUTER_HEADER_CREATION_UDP_IPV6);
	ipv6 = osmo_pfcp_bits_get(ohc->desc_bits, OSMO_PFCP_OUTER_HEADER_CREATION_IPV6);
	c_tag = osmo_pfcp_bits_get(ohc->desc_bits, OSMO_PFCP_OUTER_HEADER_CREATION_C_TAG);
	s_tag = osmo_pfcp_bits_get(ohc->desc_bits, OSMO_PFCP_OUTER_HEADER_CREATION_S_TAG);

	pos = tlv->val + 2;
	if (gtp_u_udp_ipv4 || gtp_u_udp_ipv6) {
		ENSURE_REMAINING_LENGTH_IS_AT_LEAST("TEID", pos, 4);
		ohc->teid_present = true;
		ohc->teid = osmo_load32be(pos);
		pos += 4;
	}
	if (gtp_u_udp_ipv4 || udp_ipv4 || ipv4) {
		ENSURE_REMAINING_LENGTH_IS_AT_LEAST("IPv4 address", pos, 4);
		ohc->ip_addr.v4_present = true;
		osmo_sockaddr_from_octets(&ohc->ip_addr.v4, pos, 4);
		pos += 4;
	}
	if (gtp_u_udp_ipv6 || udp_ipv6 || ipv6) {
		ENSURE_REMAINING_LENGTH_IS_AT_LEAST("IPv6 address", pos, 16);
		ohc->ip_addr.v6_present = true;
		osmo_sockaddr_from_octets(&ohc->ip_addr.v6, pos, 16);
		pos += 16;
	}
	if (udp_ipv4 || udp_ipv6) {
		ENSURE_REMAINING_LENGTH_IS_AT_LEAST("UDP port number", pos, 2);
		ohc->port_number_present = true;
		ohc->port_number = osmo_load16be(pos);
		pos += 2;
	}
	if (c_tag) {
		ohc->c_tag_present = true;
		ENSURE_REMAINING_LENGTH_IS_AT_LEAST("C-TAG", pos, 3);
		ohc->c_tag_present = true;
		ohc->c_tag = osmo_load32be_ext_2(pos, 3);
		pos += 3;
	}
	if (s_tag) {
		ohc->s_tag_present = true;
		ENSURE_REMAINING_LENGTH_IS_AT_LEAST("S-TAG", pos, 3);
		ohc->s_tag_present = true;
		ohc->s_tag = osmo_load32be_ext_2(pos, 3);
		pos += 3;
	}

	return 0;
}

int osmo_pfcp_enc_outer_header_creation(struct osmo_gtlv_put *tlv, const void *decoded_struct, const void *encode_from)
{
	const struct osmo_pfcp_ie_outer_header_creation *ohc = encode_from;
	bool gtp_u_udp_ipv4;
	bool gtp_u_udp_ipv6;
	bool udp_ipv4;
	bool udp_ipv6;
	bool ipv4;
	bool ipv6;
	bool c_tag;
	bool s_tag;

	memcpy(msgb_put(tlv->dst, sizeof(ohc->desc_bits)), ohc->desc_bits, sizeof(ohc->desc_bits));

	gtp_u_udp_ipv4 = osmo_pfcp_bits_get(ohc->desc_bits, OSMO_PFCP_OUTER_HEADER_CREATION_GTP_U_UDP_IPV4);
	udp_ipv4 = osmo_pfcp_bits_get(ohc->desc_bits, OSMO_PFCP_OUTER_HEADER_CREATION_UDP_IPV4);
	ipv4 = osmo_pfcp_bits_get(ohc->desc_bits, OSMO_PFCP_OUTER_HEADER_CREATION_IPV4);
	gtp_u_udp_ipv6 = osmo_pfcp_bits_get(ohc->desc_bits, OSMO_PFCP_OUTER_HEADER_CREATION_GTP_U_UDP_IPV6);
	udp_ipv6 = osmo_pfcp_bits_get(ohc->desc_bits, OSMO_PFCP_OUTER_HEADER_CREATION_UDP_IPV6);
	ipv6 = osmo_pfcp_bits_get(ohc->desc_bits, OSMO_PFCP_OUTER_HEADER_CREATION_IPV6);
	c_tag = osmo_pfcp_bits_get(ohc->desc_bits, OSMO_PFCP_OUTER_HEADER_CREATION_C_TAG);
	s_tag = osmo_pfcp_bits_get(ohc->desc_bits, OSMO_PFCP_OUTER_HEADER_CREATION_S_TAG);

	if ((gtp_u_udp_ipv4 || gtp_u_udp_ipv6) != (ohc->teid_present))
		RETURN_ERROR(-EINVAL, "teid_present = %s does not match the description bits 0x%02x\n",
			     ohc->teid_present ? "true" : "false",
			     ohc->desc_bits[0]);
	if (ohc->teid_present)
		msgb_put_u32(tlv->dst, ohc->teid);

	if ((gtp_u_udp_ipv4 || udp_ipv4 || ipv4) != ohc->ip_addr.v4_present)
		RETURN_ERROR(-EINVAL, "ipv4_addr_present = %s does not match the description bits 0x%02x\n",
			     ohc->ip_addr.v4_present ? "true" : "false",
			     ohc->desc_bits[0]);
	if (ohc->ip_addr.v4_present)
		osmo_sockaddr_to_octets(msgb_put(tlv->dst, 4), 4, &ohc->ip_addr.v4);

	if ((gtp_u_udp_ipv6 || udp_ipv6 || ipv6) != ohc->ip_addr.v6_present)
		RETURN_ERROR(-EINVAL, "ipv6_addr_present = %s does not match the description bits 0x%02x\n",
			     ohc->ip_addr.v6_present ? "true" : "false",
			     ohc->desc_bits[0]);
	if (ohc->ip_addr.v6_present)
		osmo_sockaddr_to_octets(msgb_put(tlv->dst, 16), 16, &ohc->ip_addr.v6);

	if ((udp_ipv4 || udp_ipv6) != ohc->port_number_present)
		RETURN_ERROR(-EINVAL, "port_number_present = %s does not match the description bits 0x%02x\n",
			     ohc->port_number_present ? "true" : "false",
			     ohc->desc_bits[0]);
	if (ohc->port_number_present)
		msgb_put_u16(tlv->dst, ohc->port_number);

	if (c_tag != ohc->c_tag_present)
		RETURN_ERROR(-EINVAL, "c_tag_present = %s does not match the description bits 0x%02x%02x\n",
			     ohc->c_tag_present ? "true" : "false",
			     ohc->desc_bits[1], ohc->desc_bits[0]);
	if (ohc->c_tag_present)
		osmo_store32be_ext(ohc->c_tag, msgb_put(tlv->dst, 3), 3);

	if (s_tag != ohc->s_tag_present)
		RETURN_ERROR(-EINVAL, "s_tag_present = %s does not match the description bits 0x%02x%02x\n",
			     ohc->s_tag_present ? "true" : "false",
			     ohc->desc_bits[1], ohc->desc_bits[0]);
	if (ohc->s_tag_present)
		osmo_store32be_ext(ohc->s_tag, msgb_put(tlv->dst, 3), 3);

	return 0;
}

int osmo_pfcp_enc_to_str_outer_header_creation(char *buf, size_t buflen, const void *encode_from)
{
	const struct osmo_pfcp_ie_outer_header_creation *ohc = encode_from;
	struct osmo_strbuf sb = { .buf = buf, .len = buflen };
	OSMO_STRBUF_APPEND(sb, osmo_pfcp_bits_to_str_buf, ohc->desc_bits, osmo_pfcp_outer_header_creation_strs);
	if (ohc->teid_present)
		OSMO_STRBUF_PRINTF(sb, ",TEID:0x%x", ohc->teid);
	OSMO_STRBUF_APPEND(sb, ip_addrs_to_str_buf, &ohc->ip_addr);
	if (ohc->port_number_present)
		OSMO_STRBUF_PRINTF(sb, ",port:%u", ohc->port_number);
	if (ohc->c_tag_present)
		OSMO_STRBUF_PRINTF(sb, ",c-tag:%u", ohc->c_tag);
	if (ohc->s_tag_present)
		OSMO_STRBUF_PRINTF(sb, ",s-tag:%u", ohc->s_tag);
	return sb.chars_needed;
}

int osmo_pfcp_dec_activate_predefined_rules(void *decoded_struct, void *decode_to, const struct osmo_gtlv_load *tlv)
{
	struct osmo_pfcp_ie_activate_predefined_rules *activate_predefined_rules = decode_to;
	osmo_strlcpy(activate_predefined_rules->str, (const char *)tlv->val, OSMO_MIN(sizeof(activate_predefined_rules->str), tlv->len+1));
	return 0;
}

int osmo_pfcp_enc_activate_predefined_rules(struct osmo_gtlv_put *tlv, const void *decoded_struct, const void *encode_from)
{
	const struct osmo_pfcp_ie_activate_predefined_rules *activate_predefined_rules = encode_from;
	unsigned int l = strlen(activate_predefined_rules->str);
	if (l)
		memcpy(msgb_put(tlv->dst, l), activate_predefined_rules->str, l);
	return 0;
}

int osmo_pfcp_enc_to_str_activate_predefined_rules(char *buf, size_t buflen, const void *encode_from)
{
	const struct osmo_pfcp_ie_activate_predefined_rules *activate_predefined_rules = encode_from;
	return osmo_quote_str_buf3(buf, buflen, activate_predefined_rules->str,
				   strnlen(activate_predefined_rules->str, sizeof(activate_predefined_rules->str)));
}

int osmo_pfcp_dec_outer_header_removal(void *decoded_struct, void *decode_to, const struct osmo_gtlv_load *tlv)
{
	struct osmo_pfcp_ie_outer_header_removal *outer_header_removal = decode_to;
	ENSURE_LENGTH_IS_AT_LEAST(1);
	outer_header_removal->desc = tlv->val[0];

	if (tlv->len > 1) {
		outer_header_removal->gtp_u_extension_header_del_present = true;
		memcpy(outer_header_removal->gtp_u_extension_header_del_bits, &tlv->val[1],
		       sizeof(outer_header_removal->gtp_u_extension_header_del_bits));
	}
	return 0;
}

int osmo_pfcp_enc_outer_header_removal(struct osmo_gtlv_put *tlv, const void *decoded_struct, const void *encode_from)
{
	const struct osmo_pfcp_ie_outer_header_removal *outer_header_removal = encode_from;
	msgb_put_u8(tlv->dst, outer_header_removal->desc);
	if (outer_header_removal->gtp_u_extension_header_del_present) {
		memcpy(msgb_put(tlv->dst, sizeof(outer_header_removal->gtp_u_extension_header_del_bits)),
		       outer_header_removal->gtp_u_extension_header_del_bits,
		       sizeof(outer_header_removal->gtp_u_extension_header_del_bits));
	}
	return 0;
}

int osmo_pfcp_enc_to_str_outer_header_removal(char *buf, size_t buflen, const void *encode_from)
{
	const struct osmo_pfcp_ie_outer_header_removal *outer_header_removal = encode_from;
	struct osmo_strbuf sb = { .buf = buf, .len = buflen };
	OSMO_STRBUF_PRINTF(sb, "%s", osmo_pfcp_outer_header_removal_desc_str(outer_header_removal->desc));
	if (outer_header_removal->gtp_u_extension_header_del_present)
		OSMO_STRBUF_PRINTF(sb, ",ext-hdr-del:0x%x", outer_header_removal->gtp_u_extension_header_del_bits[0]);
	return sb.chars_needed;
}

int osmo_pfcp_dec_ue_ip_address(void *decoded_struct, void *decode_to, const struct osmo_gtlv_load *tlv)
{
	struct osmo_pfcp_ie_ue_ip_address *ue_ip_address = decode_to;
	const uint8_t *pos;
	uint8_t flags;

	pos = tlv->val;

	ENSURE_REMAINING_LENGTH_IS_AT_LEAST("flags", pos, 1);
	flags = *pos;
	pos++;

	ue_ip_address->ipv6_prefix_length_present = flags & (1 << 6);
	ue_ip_address->chv6 = flags & (1 << 5);
	ue_ip_address->chv4 = flags & (1 << 4);
	ue_ip_address->ipv6_prefix_delegation_bits_present = flags & (1 << 3);
	ue_ip_address->ip_is_destination = flags & (1 << 2);
	ue_ip_address->ip_addr.v4_present = flags & (1 << 1);
	ue_ip_address->ip_addr.v6_present = flags & (1 << 0);

	if (ue_ip_address->ip_addr.v4_present) {
		ENSURE_REMAINING_LENGTH_IS_AT_LEAST("IPv4 address", pos, 4);
		osmo_sockaddr_from_octets(&ue_ip_address->ip_addr.v4, pos, 4);
		pos += 4;
	}
	if (ue_ip_address->ip_addr.v6_present) {
		ENSURE_REMAINING_LENGTH_IS_AT_LEAST("IPv6 address", pos, 16);
		osmo_sockaddr_from_octets(&ue_ip_address->ip_addr.v6, pos, 16);
		pos += 16;
	}

	if (ue_ip_address->ipv6_prefix_delegation_bits_present) {
		ENSURE_REMAINING_LENGTH_IS_AT_LEAST("IPv6 prefix delegation bits", pos, 1);
		ue_ip_address->ipv6_prefix_delegation_bits = *pos;
		pos++;
	}
	if (ue_ip_address->ipv6_prefix_length_present) {
		ENSURE_REMAINING_LENGTH_IS_AT_LEAST("IPv6 prefix length", pos, 1);
		ue_ip_address->ipv6_prefix_length = *pos;
		pos++;
	}

	return 0;
}

int osmo_pfcp_enc_ue_ip_address(struct osmo_gtlv_put *tlv, const void *decoded_struct, const void *encode_from)
{
	const struct osmo_pfcp_ie_ue_ip_address *ue_ip_address = encode_from;
	unsigned int l;
	uint8_t flags;

	flags = 0
		| (ue_ip_address->ipv6_prefix_length_present ? (1 << 6) : 0)
		| (ue_ip_address->chv6 ? (1 << 5) : 0)
		| (ue_ip_address->chv4 ? (1 << 4) : 0)
		| (ue_ip_address->ipv6_prefix_delegation_bits_present ? (1 << 3) : 0)
		| (ue_ip_address->ip_is_destination ? (1 << 2) : 0)
		| (ue_ip_address->ip_addr.v4_present ? (1 << 1) : 0)
		| (ue_ip_address->ip_addr.v6_present ? (1 << 0) : 0)
		;

	msgb_put_u8(tlv->dst, flags);

	if (ue_ip_address->ip_addr.v4_present) {
		if (ue_ip_address->ip_addr.v4.u.sin.sin_family != AF_INET)
			RETURN_ERROR(-EINVAL,
				     "ue_ip_address IE indicates IPv4 address, but there is no ipv4_addr");
		l = sizeof(ue_ip_address->ip_addr.v4.u.sin.sin_addr);
		osmo_sockaddr_to_octets(msgb_put(tlv->dst, l), l, &ue_ip_address->ip_addr.v4);
	}
	if (ue_ip_address->ip_addr.v6_present) {
		if (ue_ip_address->ip_addr.v6.u.sin6.sin6_family != AF_INET6)
			RETURN_ERROR(-EINVAL,
				     "ue_ip_address IE indicates IPv6 address, but there is no ipv6_addr");
		l = sizeof(ue_ip_address->ip_addr.v6.u.sin6.sin6_addr);
		osmo_sockaddr_to_octets(msgb_put(tlv->dst, l), l, &ue_ip_address->ip_addr.v6);
	}

	if (ue_ip_address->ipv6_prefix_delegation_bits_present)
		msgb_put_u8(tlv->dst, ue_ip_address->ipv6_prefix_delegation_bits);

	if (ue_ip_address->ipv6_prefix_length_present)
		msgb_put_u8(tlv->dst, ue_ip_address->ipv6_prefix_length);

	return 0;
}

int osmo_pfcp_enc_to_str_ue_ip_address(char *buf, size_t buflen, const void *encode_from)
{
	const struct osmo_pfcp_ie_ue_ip_address *uia = encode_from;
	struct osmo_strbuf sb = { .buf = buf, .len = buflen };
	if (uia->chv4)
		OSMO_STRBUF_PRINTF(sb, "chv4");
	if (uia->chv6)
		OSMO_STRBUF_PRINTF(sb, "%schv4", sb.pos ? "," : "");
	if (uia->ip_is_destination)
		OSMO_STRBUF_PRINTF(sb, "%sdst", sb.pos ? "," : "");
	OSMO_STRBUF_APPEND(sb, ip_addrs_to_str_buf, &uia->ip_addr);
	if (uia->ipv6_prefix_delegation_bits_present)
		OSMO_STRBUF_PRINTF(sb, ",ipv6-prefix-deleg:%x", uia->ipv6_prefix_delegation_bits);
	if (uia->ipv6_prefix_length_present)
		OSMO_STRBUF_PRINTF(sb, ",ipv6-prefix-len:%u", uia->ipv6_prefix_length);
	return sb.chars_needed;
}
