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

#include <osmocom/pfcp/pfcp_msg.h>

void *ctx;

/* struct osmo_sockaddr */
#define v4_ue { \
	.u.sin = { \
		.sin_family = AF_INET, \
		.sin_addr = { 0x1700a8c0 }, \
	} \
}

/* struct osmo_sockaddr */
#define v4_gtp { \
	.u.sin = { \
		.sin_family = AF_INET, \
		.sin_addr = { 0x0708090a }, \
	} \
}

/* struct osmo_pfcp_ie_f_teid */
#define f_teid_access_local { \
	.choose_flag = true, \
	.choose = { \
		.ipv4_addr = true, \
	}, \
}

/* struct osmo_pfcp_ie_f_teid */
#define f_teid_created { \
	.fixed = { \
		.teid = 1234, \
		.ip_addr = { \
			.v4_present = true, \
			.v4 = v4_gtp, \
		}, \
	}, \
}

/* struct osmo_pfcp_ie_outer_header_creation */
#define ohc_access { \
	.desc_bits = { 0x01 }, \
	.teid_present = true, \
	.teid = 0xabcdef, \
	.ip_addr = { \
		.v4_present = true, \
		.v4 = v4_gtp, \
	}, \
}

/* struct osmo_pfcp_ie_apply_action */
#define aa_forw { \
	.bits = { 0x02 }, \
}

/* struct osmo_pfcp_ie_f_seid */
#define f_seid { \
	.seid = 0x1234567890abcdef, \
	.ip_addr = { \
		.v4_present = true, \
		.v4 = v4_gtp, \
	}, \
}

struct osmo_pfcp_msg tests[] = {
	{
		.h = {
			.version = 1,
			.message_type = OSMO_PFCP_MSGT_HEARTBEAT_REQ,
			.sequence_nr = 1,
		},
		.ies.heartbeat_req = {
			.recovery_time_stamp = 1234,
		},
	},
	{
		.h = {
			.version = 1,
			.message_type = OSMO_PFCP_MSGT_HEARTBEAT_RESP,
			.sequence_nr = 2,
		},
		.ies.heartbeat_resp = {
			.recovery_time_stamp = 5678,
		},
	},
	{
		.h = {
			.version = 1,
			.message_type = OSMO_PFCP_MSGT_ASSOC_SETUP_REQ,
			.sequence_nr = 3,
		},
		.ies.assoc_setup_req = {
			.node_id = {
				.type = OSMO_PFCP_NODE_ID_T_IPV4,
				.ip.u.sin = {
					.sin_family = AF_INET,
					.sin_addr = { 0x01020304 },
				},
			},
			.recovery_time_stamp = 0x2b2b2b2b,
		},
	},
	{
		.h = {
			.version = 1,
			.message_type = OSMO_PFCP_MSGT_ASSOC_SETUP_RESP,
			.sequence_nr = 4,
		},
		.ies.assoc_setup_resp = {
			.node_id = {
				.type = OSMO_PFCP_NODE_ID_T_FQDN,
				.fqdn = "example.com",
			},
			.cause = OSMO_PFCP_CAUSE_REQUEST_ACCEPTED,
			.recovery_time_stamp = 0x2b2b2b2b,
			.up_function_features_present = true,
			.up_function_features.bits = { 1, 2 },
		},
	},
	{
		.h = {
			.version = 1,
			.message_type = OSMO_PFCP_MSGT_ASSOC_RELEASE_REQ,
			.sequence_nr = 5,
		},
		.ies.assoc_release_req = {
			.node_id = {
				.type = OSMO_PFCP_NODE_ID_T_IPV6,
				.ip.u.sin6 = {
					.sin6_family = AF_INET6,
					.sin6_addr = {{{ 1, 2, 3, 4 }}},
				},
			},
		},
	},
	{
		.h = {
			.version = 1,
			.message_type = OSMO_PFCP_MSGT_ASSOC_RELEASE_RESP,
			.sequence_nr = 6,
		},
		.ies.assoc_release_resp = {
			.node_id = {
				.type = OSMO_PFCP_NODE_ID_T_IPV4,
				.ip.u.sin = {
					.sin_family = AF_INET,
					.sin_addr = { 0x01020304 },
				},
			},
			.cause = OSMO_PFCP_CAUSE_REQUEST_REJECTED,
		},
	},
	{
		.h = {
			.version = 1,
			.message_type = OSMO_PFCP_MSGT_SESSION_EST_REQ,
			.sequence_nr = 7,
			.seid_present = true,
			.seid = 0,
		},
		.ies.session_est_req = {
			.node_id = {
				.type = OSMO_PFCP_NODE_ID_T_IPV4,
				.ip.u.sin = {
					.sin_family = AF_INET,
					.sin_addr = { 0x0100007f },
				},
			},
			.cp_f_seid_present = true,
			.cp_f_seid = f_seid,
			.create_pdr_count = 2,
			.create_pdr = {
				{
					.pdr_id = 1,
					.precedence = 255,
					.pdi = {
						.source_iface = OSMO_PFCP_SOURCE_IFACE_CORE,
						.ue_ip_address_present = true,
						.ue_ip_address = {
							.ip_is_destination = true,
							.ip_addr = {
								.v4_present = true,
								.v4 = v4_ue,
							},
						},
					},
					.far_id_present = true,
					.far_id = 1,
				},
				{
					.pdr_id = 2,
					.precedence = 255,
					.pdi = {
						.source_iface = OSMO_PFCP_SOURCE_IFACE_ACCESS,
						.local_f_teid_present = true,
						.local_f_teid = f_teid_access_local,
					},
					.outer_header_removal_present = true,
					.outer_header_removal = {
						.desc = OSMO_PFCP_OUTER_HEADER_REMOVAL_GTP_U_UDP_IPV4,
					},
					.far_id_present = true,
					.far_id = 2,
				},
			},
			.create_far_count = 2,
			.create_far = {
				{
					.far_id = 1,
					.forw_params_present = true,
					.forw_params = {
						.destination_iface = OSMO_PFCP_DEST_IFACE_ACCESS,
						.outer_header_creation_present = true,
						.outer_header_creation = ohc_access,
					},
					.apply_action = aa_forw,
				},
				{
					.far_id = 2,
					.forw_params_present = true,
					.forw_params = {
						.destination_iface = OSMO_PFCP_DEST_IFACE_CORE,
					},
					.apply_action = aa_forw,
				},
			},
		},
	},
	{
		.h = {
			.version = 1,
			.message_type = OSMO_PFCP_MSGT_SESSION_EST_RESP,
			.sequence_nr = 8,
			.seid_present = true,
			.seid = 0x0123456789abcdef,
		},
		.ies.session_est_resp = {
			.node_id = {
				.type = OSMO_PFCP_NODE_ID_T_IPV4,
				.ip.u.sin = {
					.sin_family = AF_INET,
					.sin_addr = { 0x0200007f },
				},
			},
			.cause = OSMO_PFCP_CAUSE_REQUEST_ACCEPTED,
			.up_f_seid_present = true,
			.up_f_seid = f_seid,
			.created_pdr_count = 2,
			.created_pdr = {
				{
					.pdr_id = 1,
				},
				{
					.pdr_id = 2,
					.local_f_teid_present = true,
					.local_f_teid = f_teid_created,
				},
			},
		},
	},
	{
		.h = {
			.version = 1,
			.message_type = OSMO_PFCP_MSGT_SESSION_MOD_REQ,
			.sequence_nr = 9,
			.seid_present = true,
			.seid = 0,
		},
		.ies.session_mod_req = {
			.remove_pdr_count = 1,
			.remove_pdr = {
				{
					.pdr_id = 1,
				},
			},
			.remove_far_count = 1,
			.remove_far = {
				{
					.far_id = 1,
				},
			},
			.create_pdr_count = 1,
			.create_pdr = {
				{
					.pdr_id = 3,
					.precedence = 255,
					.pdi = {
						.source_iface = OSMO_PFCP_SOURCE_IFACE_ACCESS,
						.local_f_teid_present = true,
						.local_f_teid = f_teid_access_local,
					},
					.outer_header_removal_present = true,
					.outer_header_removal = {
						.desc = OSMO_PFCP_OUTER_HEADER_REMOVAL_GTP_U_UDP_IPV4,
					},
					.far_id_present = true,
					.far_id = 3,
				},
			},
			.create_far_count = 1,
			.create_far = {
				{
					.far_id = 3,
					.forw_params_present = true,
					.forw_params = {
						.destination_iface = OSMO_PFCP_DEST_IFACE_ACCESS,
						.outer_header_creation_present = true,
						.outer_header_creation = ohc_access,
					},
					.apply_action = aa_forw,
				},
			},
			.upd_pdr_count = 1,
			.upd_pdr = {
				{
					.pdr_id = 1,
					.pdi = {
						.source_iface = OSMO_PFCP_SOURCE_IFACE_ACCESS,
						.local_f_teid_present = true,
						.local_f_teid = f_teid_access_local,
					},
					.outer_header_removal_present = true,
					.outer_header_removal = {
						.desc = OSMO_PFCP_OUTER_HEADER_REMOVAL_GTP_U_UDP_IPV4,
					},
					.far_id_present = true,
					.far_id = 1,
				},
			},
			.upd_far_count = 1,
			.upd_far = {
				{
					.far_id = 1,
					.upd_forw_params_present = true,
					.upd_forw_params = {
						.destination_iface = OSMO_PFCP_DEST_IFACE_CORE,
						.network_inst_present = true,
						.network_inst = {
							.str = "internet",
						},
					},
					.apply_action = aa_forw,
				},
			},
		},
	},
	{
		.h = {
			.version = 1,
			.message_type = OSMO_PFCP_MSGT_SESSION_MOD_RESP,
			.sequence_nr = 10,
			.seid_present = true,
			.seid = 0x0123456789abcdef,
		},
		.ies.session_mod_resp = {
			.cause = OSMO_PFCP_CAUSE_REQUEST_ACCEPTED,
			.created_pdr_count = 1,
			.created_pdr = {
				{
					.pdr_id = 3,
					.local_f_teid_present = true,
					.local_f_teid = f_teid_created,
				},
			},
			.updated_pdr_count = 1,
			.updated_pdr = {
				{
					.pdr_id = 1,
					.local_f_teid_present = true,
					.local_f_teid = f_teid_created,
				},
			},
		},
	},
	{
		.h = {
			.version = 1,
			.message_type = OSMO_PFCP_MSGT_SESSION_MOD_RESP,
			.sequence_nr = 11,
			.seid_present = true,
			.seid = 0x0123456789abcdef,
		},
		.ies.session_mod_resp = {
			.cause = OSMO_PFCP_CAUSE_MANDATORY_IE_MISSING,
			.offending_ie_present = true,
			.offending_ie = OSMO_PFCP_IEI_APPLY_ACTION,
		},
	},
	{
		.h = {
			.version = 1,
			.message_type = OSMO_PFCP_MSGT_SESSION_DEL_REQ,
			.sequence_nr = 12,
			.seid_present = true,
			.seid = 0x0123456789abcdef,
		},
	},
	{
		.h = {
			.version = 1,
			.message_type = OSMO_PFCP_MSGT_SESSION_DEL_RESP,
			.sequence_nr = 13,
			.seid_present = true,
			.seid = 0x0123456789abcdef,
		},
		.ies.session_del_resp = {
			.cause = OSMO_PFCP_CAUSE_NO_ESTABLISHED_PFCP_ASSOC,
		},
	},
	{
		.h = {
			.version = 1,
			.message_type = OSMO_PFCP_MSGT_SESSION_DEL_RESP,
			.sequence_nr = 13,
			.seid_present = true,
			.seid = 0x0123456789abcdef,
		},
		.ies.session_del_resp = {
			.cause = OSMO_PFCP_CAUSE_REQUEST_ACCEPTED,
		},
	},
};

void test_enc_dec(void)
{
	int i;
	for (i = 0; i < ARRAY_SIZE(tests); i++) {
		void *loop_ctx = talloc_named_const(ctx, 0, "loop");
		int rc;
		const struct osmo_pfcp_msg *orig = &tests[i];
		struct osmo_pfcp_msg parsed = {};
		struct msgb *msg;
		struct osmo_gtlv_load tlv;

		printf("\n=== start %s[%d]\n", __func__, i);
		printf("encoding: %s\n", osmo_pfcp_message_type_str(orig->h.message_type));
		printf("%s\n", osmo_pfcp_msg_to_str_c(loop_ctx, orig));
		msg = msgb_alloc(1024, __func__);
		rc = osmo_pfcp_msg_encode(msg, orig);
		printf("osmo_pfcp_msg_encode() rc = %d\n", rc);
		printf("%s.\n", osmo_hexdump(msg->data, msg->len));

		rc = osmo_pfcp_msg_decode_header(&tlv, &parsed, msg);
		printf("osmo_pfcp_msg_decode_header() rc = %d\n", rc);
		if (rc != msgb_length(msg)) {
			printf("ERROR: expected rc = %d\n", msgb_length(msg));
			exit(1);
		} else {
			printf("rc == msgb_length()\n");
		}

		rc = osmo_pfcp_msg_decode_tlv(&parsed, &tlv);
		printf("osmo_pfcp_msg_decode_tlv() rc = %d\n", rc);

		if (strcmp(osmo_pfcp_msg_to_str_c(loop_ctx, orig),
			   osmo_pfcp_msg_to_str_c(loop_ctx, &parsed))) {
			printf(" ERROR: parsed != orig\n");
			printf("   orig: %s\n",
			       osmo_pfcp_msg_to_str_c(loop_ctx, orig));
			printf(" parsed: %s\n",
			       osmo_pfcp_msg_to_str_c(loop_ctx, &parsed));
			exit(1);
		} else {
			printf("parsed == orig\n");
		}

		msgb_free(msg);
		printf("=== end %s[%d]\n", __func__, i);
		talloc_free(loop_ctx);
	}
}

int main(int argc, char **argv)
{
	ctx = talloc_named_const(NULL, 0, "pfcp_test");
	msgb_talloc_ctx_init(ctx, 0);

	test_enc_dec();

	talloc_free(ctx);
	return 0;
}
