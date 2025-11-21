/* Tool to generate C source code of structs and IE arrays for de- and encoding PFCP messages. */
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

#define Ms(MEMB_NAME) M(MEMB_NAME, #MEMB_NAME)
#define Os(MEMB_NAME) O(MEMB_NAME, #MEMB_NAME)
#define O_MULTIs(N, MEMB_NAME) O_MULTI(N, MEMB_NAME, #MEMB_NAME)
#define M_MULTIs(N, M, MEMB_NAME) M_MULTI(N, M, MEMB_NAME, #MEMB_NAME)

static const struct osmo_gtlv_gen_ie recovery_time_stamp = {
	"uint32_t",
	.dec_enc = "32be",
	.spec_ref = "7.4.2",
};

static const struct osmo_gtlv_gen_ie cause = {
	"enum osmo_pfcp_cause",
	.spec_ref = "8.2.1",
};

static const struct osmo_gtlv_gen_ie offending_ie = {
	.decoded_type = "enum osmo_pfcp_iei",
	.spec_ref = "8.2.22",
};

static const struct osmo_gtlv_gen_ie f_seid = {
	.tag_name = "f_seid",
	.spec_ref = "8.2.37",
};

static const struct osmo_gtlv_gen_ie pdr_id = {
	.decoded_type = "uint16_t",
	.dec_enc = "16be",
	.spec_ref = "8.2.36",
};

static const struct osmo_gtlv_gen_ie precedence = {
	.decoded_type = "uint32_t",
	.dec_enc = "32be",
	.spec_ref = "8.2.11",
};

static const struct osmo_gtlv_gen_ie source_iface = {
	.decoded_type = "enum osmo_pfcp_source_iface",
	.spec_ref = "8.2.2",
};

static const struct osmo_gtlv_gen_ie f_teid = {
	.tag_name = "f_teid",
	.spec_ref = "8.2.3",
};

static const struct osmo_gtlv_gen_ie traffic_endpoint_id = {
	.tag_name = "traffic_endpoint_id",
	.decoded_type = "uint8_t",
	.dec_enc = "8",
	.spec_ref = "8.2.92",
};

static const struct osmo_gtlv_gen_ie iface_type = {
	.decoded_type = "enum osmo_pfcp_3gpp_iface_type",
	.tag_name = "3gpp_iface_type",
	.spec_ref = "8.2.118",
};

static const struct osmo_gtlv_gen_ie_o ies_in_pdi[] = {
	Ms(source_iface),
	O(f_teid, "local_f_teid"),
	O(ALL_FROM_NAME, "network_inst"),
	O(ALL_FROM_NAME, "ue_ip_address"),
	Os(traffic_endpoint_id),
	O(iface_type, "source_iface_type"),
	{}
};

static const struct osmo_gtlv_gen_ie pdi = {
	.nested_ies = ies_in_pdi,
	.spec_ref = "7.5.2.2-2",
};

static const struct osmo_gtlv_gen_ie far_id = {
	.decoded_type = "uint32_t",
	.dec_enc = "32be",
	.spec_ref = "8.2.74",
};

static const struct osmo_gtlv_gen_ie_o ies_in_create_pdr[] = {
	Ms(pdr_id),
	Ms(precedence),
	Ms(pdi),
	O(ALL_FROM_NAME, "outer_header_removal"),
	Os(far_id),
	O(ALL_FROM_NAME, "activate_predefined_rules"),
	{}
};

static const struct osmo_gtlv_gen_ie create_pdr = {
	.nested_ies = ies_in_create_pdr,
	.spec_ref = "7.5.2.2",
};

static const struct osmo_gtlv_gen_ie_o ies_in_created_pdr[] = {
	Ms(pdr_id),
	O(f_teid, "local_f_teid"),
	{}
};

static const struct osmo_gtlv_gen_ie created_pdr = {
	.nested_ies = ies_in_created_pdr,
	.spec_ref = "7.5.3.2",
};

static const struct osmo_gtlv_gen_ie_o ies_in_upd_pdr[] = {
	Ms(pdr_id),
	O(ALL_FROM_NAME, "outer_header_removal"),
	Os(pdi),
	Os(far_id),
	O(ALL_FROM_NAME, "activate_predefined_rules"),
	{}
};

static const struct osmo_gtlv_gen_ie upd_pdr = {
	.nested_ies = ies_in_upd_pdr,
	.spec_ref = "7.5.4.2",
};

static const struct osmo_gtlv_gen_ie_o ies_in_updated_pdr[] = {
	Ms(pdr_id),
	O(f_teid, "local_f_teid"),
	{}
};

static const struct osmo_gtlv_gen_ie updated_pdr = {
	.nested_ies = ies_in_updated_pdr,
	.spec_ref = "7.5.9.3",
};

static const struct osmo_gtlv_gen_ie_o ies_in_remove_pdr[] = {
	Ms(pdr_id),
	{}
};

static const struct osmo_gtlv_gen_ie remove_pdr = {
	.nested_ies = ies_in_remove_pdr,
	.spec_ref = "7.5.4.6",
};

static const struct osmo_gtlv_gen_ie destination_iface = {
	.decoded_type = "enum osmo_pfcp_dest_iface",
	.dec_enc = "dest_iface",
	.spec_ref = "8.2.24",
};

static const struct osmo_gtlv_gen_ie_o ies_in_forw_params[] = {
	Ms(destination_iface),
	O(ALL_FROM_NAME, "network_inst"),
	O(ALL_FROM_NAME, "outer_header_creation"),
	O(traffic_endpoint_id, "linked_te_id"),
	O(iface_type, "destination_iface_type"),
	{}
};

static const struct osmo_gtlv_gen_ie forw_params = {
	.nested_ies = ies_in_forw_params,
	.spec_ref = "7.5.2.3-2",
};

static const struct osmo_gtlv_gen_ie_o ies_in_upd_forw_params[] = {
	Os(destination_iface),
	O(ALL_FROM_NAME, "network_inst"),
	O(ALL_FROM_NAME, "outer_header_creation"),
	O(traffic_endpoint_id, "linked_te_id"),
	O(iface_type, "destination_iface_type"),
	{}
};

static const struct osmo_gtlv_gen_ie upd_forw_params = {
	.nested_ies = ies_in_upd_forw_params,
	.spec_ref = "7.5.4.3-2",
};

static const struct osmo_gtlv_gen_ie_o ies_in_create_far[] = {
	Ms(far_id),
	M(ALL_FROM_NAME, "apply_action"),
	Os(forw_params),
	{}
};

static const struct osmo_gtlv_gen_ie create_far = {
	.nested_ies = ies_in_create_far,
	.spec_ref = "7.5.2.3",
};

static const struct osmo_gtlv_gen_ie_o ies_in_remove_far[] = {
	Ms(far_id),
	{}
};

static const struct osmo_gtlv_gen_ie remove_far = {
	.nested_ies = ies_in_remove_far,
	.spec_ref = "7.5.4.6",
};

static const struct osmo_gtlv_gen_ie_o ies_in_upd_far[] = {
	Ms(far_id),
	O(ALL_FROM_NAME, "apply_action"),
	Os(upd_forw_params),
	{}
};

static const struct osmo_gtlv_gen_ie upd_far = {
	.nested_ies = ies_in_upd_far,
	.spec_ref = "7.5.4.3",
};

static const struct osmo_gtlv_gen_ie_o ies_in_msg_heartbeat_req[] = {
	Ms(recovery_time_stamp),
	{}
};

static const struct osmo_gtlv_gen_ie_o ies_in_msg_heartbeat_resp[] = {
	Ms(recovery_time_stamp),
	{}
};

static const struct osmo_gtlv_gen_ie_o ies_in_msg_assoc_setup_req[] = {
	M(ALL_FROM_NAME, "node_id"),
	Ms(recovery_time_stamp),
	O(ALL_FROM_NAME, "up_function_features"),
	O(ALL_FROM_NAME, "cp_function_features"),
	{}
};

static const struct osmo_gtlv_gen_ie_o ies_in_msg_assoc_setup_resp[] = {
	M(ALL_FROM_NAME, "node_id"),
	Ms(cause),
	Ms(recovery_time_stamp),
	O(ALL_FROM_NAME, "up_function_features"),
	O(ALL_FROM_NAME, "cp_function_features"),
	{}
};

static const struct osmo_gtlv_gen_ie_o ies_in_msg_assoc_release_req[] = {
	M(ALL_FROM_NAME, "node_id"),
	{}
};

static const struct osmo_gtlv_gen_ie_o ies_in_msg_assoc_release_resp[] = {
	M(ALL_FROM_NAME, "node_id"),
	Ms(cause),
	{}
};

static const struct osmo_gtlv_gen_ie_o ies_in_msg_session_est_req[] = {
	M(ALL_FROM_NAME, "node_id"),
	O(f_seid, "cp_f_seid"),
	M_MULTIs(32, 1, create_pdr),
	M_MULTI(32, 1, create_far, "create_far"),
	{}
};

static const struct osmo_gtlv_gen_ie_o ies_in_msg_session_est_resp[] = {
	M(ALL_FROM_NAME, "node_id"),
	Ms(cause),
	Os(offending_ie),
	O(f_seid, "up_f_seid"),
	O_MULTIs(32, created_pdr),
	{}
};

static const struct osmo_gtlv_gen_ie_o ies_in_msg_session_mod_req[] = {
	O(f_seid, "cp_f_seid"),
	O_MULTIs(32, remove_pdr),
	O_MULTIs(32, remove_far),
	O_MULTIs(32, create_pdr),
	O_MULTIs(32, create_far),
	O_MULTIs(32, upd_pdr),
	O_MULTIs(32, upd_far),
	{}
};

static const struct osmo_gtlv_gen_ie_o ies_in_msg_session_mod_resp[] = {
	Ms(cause),
	Os(offending_ie),
	O_MULTIs(32, created_pdr),
	O_MULTIs(32, updated_pdr),
	{}
};

static const struct osmo_gtlv_gen_ie_o ies_in_msg_session_del_req[] = {
	O(ALL_FROM_NAME, "tl_container"),
	O(ALL_FROM_NAME, "node_id"),
	O(f_seid, "cp_f_seid"),
	{}
};

static const struct osmo_gtlv_gen_ie_o ies_in_msg_session_del_resp[] = {
	Ms(cause),
	{}
};

#define MSG(NAME) { #NAME, ies_in_msg_##NAME }
static const struct osmo_gtlv_gen_msg pfcp_msg_defs[] = {
	MSG(heartbeat_req),
	MSG(heartbeat_resp),
	MSG(assoc_setup_req),
	MSG(assoc_setup_resp),
	MSG(assoc_release_req),
	MSG(assoc_release_resp),
	MSG(session_est_req),
	MSG(session_est_resp),
	MSG(session_mod_req),
	MSG(session_mod_resp),
	MSG(session_del_req),
	MSG(session_del_resp),
	{}
};

int main(int argc, const char **argv)
{
	struct osmo_gtlv_gen_cfg cfg = {
		.proto_name = "osmo_pfcp",
		.spec_ref_prefix = "3GPP TS 29.244 ",
		.message_type_enum = "enum osmo_pfcp_message_type",
		.message_type_prefix = "OSMO_PFCP_MSGT_",
		.tag_enum = "enum osmo_pfcp_iei",
		.tag_prefix = "OSMO_PFCP_IEI_",
		.decoded_type_prefix = "struct osmo_pfcp_ie_",
		.h_header = "#include <osmocom/pfcp/pfcp_ies_custom.h>",
		.c_header = "#include <osmocom/pfcp/pfcp_ies_auto.h>",
		.msg_defs = pfcp_msg_defs,
		.add_enc_to_str = true,
	};
	return osmo_gtlv_gen_main(&cfg, argc, argv);
}
