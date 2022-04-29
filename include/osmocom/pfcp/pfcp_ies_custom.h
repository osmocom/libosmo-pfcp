/* Definitions for decoded PFCP IEs, to be used by the auto-generated pfcp_ies_auto.c. */
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

#include <osmocom/core/socket.h>

#include <osmocom/pfcp/pfcp_proto.h>

/* Common pattern used in various PFCP IEs. */
struct osmo_pfcp_ip_addrs {
	bool v4_present;
	struct osmo_sockaddr v4;
	bool v6_present;
	struct osmo_sockaddr v6;
};

int osmo_pfcp_ip_addrs_set(struct osmo_pfcp_ip_addrs *dst, const struct osmo_sockaddr *addr);

/* 3GPP TS 29.244 8.2.38, IETF RFC 1035 3.1 */
struct osmo_pfcp_ie_node_id {
	enum osmo_pfcp_node_id_type type;
	union {
		struct osmo_sockaddr ip;
		/* Fully qualified domain name in "dot" notation ("host.example.com") */
		char fqdn[254];
	};
};

int osmo_pfcp_ie_node_id_to_str_buf(char *buf, size_t buflen, const struct osmo_pfcp_ie_node_id *node_id);
char *osmo_pfcp_ie_node_id_to_str_c(void *ctx, const struct osmo_pfcp_ie_node_id *node_id);

bool osmo_pfcp_bits_get(const uint8_t *bits, unsigned int bitpos);
void osmo_pfcp_bits_set(uint8_t *bits, unsigned int bitpos, bool val);
int osmo_pfcp_bits_to_str_buf(char *buf, size_t buflen, const uint8_t *bits, const struct value_string *bit_strs);
char *osmo_pfcp_bits_to_str_c(void *ctx, const uint8_t *bits, const struct value_string *bit_str);

/* 3GPP TS 29.244 8.2.25
 * Usage:
 *     struct osmo_pfcp_ie_up_function_features x;
 *     osmo_pfcp_bits_set(x.bits, OSMO_PFCP_UP_FEAT_BUNDL, true);
 *     if (osmo_pfcp_bits_get(x.bits, OSMO_PFCP_UP_FEAT_BUNDL))
 *             foo();
 *     printf("%s\n", osmo_pfcp_bits_to_str_c(x.bits, osmo_pfcp_up_feature_strs));
 */
struct osmo_pfcp_ie_up_function_features {
	uint8_t bits[6];
};

/* 3GPP TS 29.244 8.2.58
 *     struct osmo_pfcp_ie_cp_function_features x;
 *     osmo_pfcp_bits_set(x.bits, OSMO_PFCP_CP_FEAT_BUNDL, true);
 *     if (osmo_pfcp_bits_get(x.bits, OSMO_PFCP_CP_FEAT_BUNDL))
 *             foo();
 *     printf("%s\n", osmo_pfcp_bits_to_str_c(x.bits, osmo_pfcp_cp_feature_strs));
 */
struct osmo_pfcp_ie_cp_function_features {
	uint8_t bits[1];
};

/* 3GPP TS 29.244 8.2.37 */
struct osmo_pfcp_ie_f_seid {
	uint64_t seid;
	struct osmo_pfcp_ip_addrs ip_addr;
};

void osmo_pfcp_ie_f_seid_set(struct osmo_pfcp_ie_f_seid *f_seid, uint64_t seid,
			     const struct osmo_sockaddr *remote_addr);

/* 3GPP TS 29.244 8.3.2 */
struct osmo_pfcp_ie_f_teid {
	bool choose_flag;
	union {
		struct {
			uint32_t teid;
			struct osmo_pfcp_ip_addrs ip_addr;
		} fixed;
		struct {
			bool ipv4_addr;
			bool ipv6_addr;
			bool choose_id_present;
			uint8_t choose_id;
		} choose;
	};
};

/* 3GPP TS 29.244 8.2.62 */
struct osmo_pfcp_ie_ue_ip_address {
	bool chv6;
	bool chv4;
	bool ip_is_destination;
	struct osmo_pfcp_ip_addrs ip_addr;
	bool ipv6_prefix_delegation_bits_present;
	uint8_t ipv6_prefix_delegation_bits;
	bool ipv6_prefix_length_present;
	uint8_t ipv6_prefix_length;
};

/* 3GPP TS 29.244 8.2.26.
 * Usage:
 *     struct osmo_pfcp_ie_apply_action x;
 *     osmo_pfcp_bits_set(x.bits, OSMO_PFCP_APPLY_ACTION_FORW, true);
 *     if (osmo_pfcp_bits_get(x.bits, OSMO_PFCP_APPLY_ACTION_FORW))
 *             foo();
 *     printf("%s\n", osmo_pfcp_bits_to_str_c(x.bits, osmo_pfcp_apply_action_strs));
 */
struct osmo_pfcp_ie_apply_action {
	uint8_t bits[2];
};

struct osmo_pfcp_ie_network_inst {
	/* A domain name may have up to 253 characters; plus nul. */
	char str[253+1];
};

struct osmo_pfcp_ie_activate_predefined_rules {
	char str[256];
};

/* 3GPP TS 29.244 8.2.56 */
struct osmo_pfcp_ie_outer_header_creation {
	/* desc_bits Usage:
	 *     osmo_pfcp_bits_set(x.desc_bits, OSMO_PFCP_OUTER_HEADER_CREATION_GTP_U_UDP_IPV4, true);
	 *     if (osmo_pfcp_bits_get(x.desc_bits, OSMO_PFCP_OUTER_HEADER_CREATION_GTP_U_UDP_IPV4))
	 *             foo();
	 *     printf("%s\n", osmo_pfcp_bits_to_str_c(x.desc_bits, osmo_pfcp_outer_header_creation_strs));
	 */
	uint8_t desc_bits[2];
	bool teid_present;
	uint32_t teid;
	struct osmo_pfcp_ip_addrs ip_addr;
	bool port_number_present;
	uint16_t port_number;
	bool c_tag_present;
	uint32_t c_tag;
	bool s_tag_present;
	uint32_t s_tag;
};

/* 3GPP TS 29.244 8.2.64. */
struct osmo_pfcp_ie_outer_header_removal {
	enum osmo_pfcp_outer_header_removal_desc desc;
	bool gtp_u_extension_header_del_present;
	uint8_t gtp_u_extension_header_del_bits[1];
};
