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

#include <osmocom/core/utils.h>

#include <osmocom/pfcp/pfcp_proto.h>

extern const struct value_string osmo_pfcp_message_type_strs[];
static inline const char *osmo_pfcp_message_type_str(enum osmo_pfcp_message_type val)
{
	return get_value_string(osmo_pfcp_message_type_strs, val);
}

extern const struct value_string osmo_pfcp_iei_strs[];
static inline const char *osmo_pfcp_iei_str(enum osmo_pfcp_iei val)
{
	return get_value_string(osmo_pfcp_iei_strs, val);
}

extern const struct value_string osmo_pfcp_cause_strs[];
static inline const char *osmo_pfcp_cause_str(enum osmo_pfcp_cause val)
{
	return get_value_string(osmo_pfcp_cause_strs, val);
}

extern const struct value_string osmo_pfcp_up_feature_strs[];
static inline const char *osmo_pfcp_up_feature_str(enum osmo_pfcp_up_feature val)
{
	return get_value_string(osmo_pfcp_up_feature_strs, val);
}

extern const struct value_string osmo_pfcp_cp_feature_strs[];
static inline const char *osmo_pfcp_cp_feature_str(enum osmo_pfcp_cp_feature val)
{
	return get_value_string(osmo_pfcp_cp_feature_strs, val);
}

extern const struct value_string osmo_pfcp_apply_action_strs[];
static inline const char *osmo_pfcp_apply_action_str(enum osmo_pfcp_apply_action val)
{
	return get_value_string(osmo_pfcp_apply_action_strs, val);
}

extern const struct value_string osmo_pfcp_outer_header_creation_strs[];
static inline const char *osmo_pfcp_outer_header_creation_str(enum osmo_pfcp_outer_header_creation val)
{
	return get_value_string(osmo_pfcp_outer_header_creation_strs, val);
}

extern const struct value_string osmo_pfcp_outer_header_removal_desc_strs[];
static inline const char *osmo_pfcp_outer_header_removal_desc_str(enum osmo_pfcp_outer_header_removal_desc val)
{
	return get_value_string(osmo_pfcp_outer_header_removal_desc_strs, val);
}

extern const struct value_string osmo_pfcp_source_iface_strs[];
static inline const char *osmo_pfcp_source_iface_str(enum osmo_pfcp_source_iface val)
{
	return get_value_string(osmo_pfcp_source_iface_strs, val);
}

extern const struct value_string osmo_pfcp_dest_iface_strs[];
static inline const char *osmo_pfcp_dest_iface_str(enum osmo_pfcp_dest_iface val)
{
	return get_value_string(osmo_pfcp_dest_iface_strs, val);
}

extern const struct value_string osmo_pfcp_3gpp_iface_type_strs[];
static inline const char *osmo_pfcp_3gpp_iface_type_str(enum osmo_pfcp_3gpp_iface_type val)
{
	return get_value_string(osmo_pfcp_3gpp_iface_type_strs, val);
}
