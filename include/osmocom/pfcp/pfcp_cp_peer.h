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

#include <stdint.h>
#include <stdbool.h>

#include <osmocom/core/socket.h>
#include <osmocom/core/use_count.h>
#include <osmocom/pfcp/pfcp_proto.h>

struct osmo_fsm_inst;
struct osmo_pfcp_endpoint;
struct osmo_pfcp_cp_peer;

typedef void (*osmo_pfcp_cp_peer_assoc_cb)(struct osmo_pfcp_cp_peer *cp_peer, bool associated);

struct osmo_pfcp_cp_peer *osmo_pfcp_cp_peer_alloc(void *ctx,
						  struct osmo_pfcp_endpoint *ep,
						  const struct osmo_sockaddr *remote_addr);
int osmo_pfcp_cp_peer_associate(struct osmo_pfcp_cp_peer *cp_peer);
bool osmo_pfcp_cp_peer_is_associated(const struct osmo_pfcp_cp_peer *cp_peer);
int osmo_pfcp_cp_peer_set_associated_cb(struct osmo_pfcp_cp_peer *cp_peer, osmo_pfcp_cp_peer_assoc_cb assoc_cb);

uint64_t osmo_pfcp_cp_peer_next_seid(struct osmo_pfcp_cp_peer *cp_peer);
const struct osmo_sockaddr *osmo_pfcp_cp_peer_get_remote_addr(const struct osmo_pfcp_cp_peer *cp_peer);

void *osmo_pfcp_cp_peer_get_priv(struct osmo_pfcp_cp_peer *cp_peer);
void osmo_pfcp_cp_peer_set_priv(struct osmo_pfcp_cp_peer *cp_peer, void *priv);

struct osmo_pfcp_msg *osmo_pfcp_cp_peer_new_req(struct osmo_pfcp_cp_peer *cp_peer,
						enum osmo_pfcp_message_type msg_type);
struct osmo_pfcp_msg *osmo_pfcp_cp_peer_new_resp(struct osmo_pfcp_cp_peer *cp_peer,
						 const struct osmo_pfcp_msg *in_reply_to,
						 enum osmo_pfcp_message_type msg_type);
void osmo_pfcp_cp_peer_set_msg_ctx(struct osmo_pfcp_cp_peer *cp_peer, struct osmo_pfcp_msg *m);
