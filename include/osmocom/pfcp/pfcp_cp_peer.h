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

struct osmo_pfcp_cp_peer {
	struct osmo_fsm_inst *fi;
	struct osmo_pfcp_endpoint *ep;
	struct osmo_sockaddr remote_addr;
	uint64_t next_seid_state;

	/* If non-NULL, called whenever the peer completes a PFCP Association, and when it loses association.
	 * Argument associated == true means the peer has just associated;
	 * associated == false means the association has been lost. */
	osmo_pfcp_cp_peer_assoc_cb assoc_cb;
	/* Application private data for assoc_cb, in case ep->priv does not suffice. */
	void *priv;

	struct osmo_use_count use_count;
	struct osmo_use_count_entry use_count_buf[128];
};

struct osmo_pfcp_cp_peer *osmo_pfcp_cp_peer_alloc(void *ctx,
						  struct osmo_pfcp_endpoint *ep,
						  const struct osmo_sockaddr *remote_addr);
int osmo_pfcp_cp_peer_associate(struct osmo_pfcp_cp_peer *cp_peer);
bool osmo_pfcp_cp_peer_is_associated(const struct osmo_pfcp_cp_peer *cp_peer);
struct osmo_pfcp_msg *osmo_pfcp_cp_peer_new_msg_tx(struct osmo_pfcp_cp_peer *cp_peer,
						   enum osmo_pfcp_message_type msg_type);
void osmo_pfcp_cp_peer_set_msg_ctx(struct osmo_pfcp_cp_peer *cp_peer, struct osmo_pfcp_msg *m);
