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
#include <osmocom/core/select.h>
#include <osmocom/core/tdef.h>

#include <osmocom/pfcp/pfcp_msg.h>

struct osmo_pfcp_endpoint;
struct osmo_fsm_inst;

enum osmo_pfcp_timers {
	OSMO_PFCP_TIMER_HEARTBEAT_REQ = -19,
	OSMO_PFCP_TIMER_HEARTBEAT_RESP = -20,
	OSMO_PFCP_TIMER_GRACEFUL_REL = -21,
	OSMO_PFCP_TIMER_T1 = -22,
	OSMO_PFCP_TIMER_N1 = -23,
	OSMO_PFCP_TIMER_KEEP_RESP = -24,
	OSMO_PFCP_TIMER_ASSOC_RETRY = -26,
};

extern struct osmo_tdef osmo_pfcp_tdefs[];

/* Ownership of m remains with the caller / m will be deallocated by the caller.
 * \param ep  The PFCP endpoint that received and decoded the message.
 * \param m  The message that was received.
 * \param req  If m is a PFCP Response to an earlier Request, req is that request message. Otherwise req is NULL.
 */
typedef void (*osmo_pfcp_endpoint_cb)(struct osmo_pfcp_endpoint *ep, struct osmo_pfcp_msg *m,
				      struct osmo_pfcp_msg *req);

/* Send/receive PFCP messages to/from remote PFCP endpoints. */
struct osmo_pfcp_endpoint;

struct osmo_pfcp_endpoint_cfg {
	/* Local address */
	struct osmo_sockaddr local_addr;
	/* Local PFCP Node ID, as sent in outgoing messages' Node ID IE */
	struct osmo_pfcp_ie_node_id local_node_id;

	/* If non-NULL, this function is called just after decoding and before handling the osmo_pfcp_msg passed as
	 * argument m.
	 * The caller (you) usually implements this to set m->ctx.peer_fi and m->ctx.session_fi as appropriate,
	 * so that these are used for logging context during message handling. The caller may also use m->ctx.peer_fi
	 * and m->ctx.session_fi pointers to reduce lookup iterations in e.g. rx_msg(). */
	osmo_pfcp_endpoint_cb set_msg_ctx_cb;

	/* Callback to receive a single incoming PFCP message from a remote peer, already decoded. See also the doc for
	 * osmo_pfcp_endpoint_cb.
	 * All incoming messages are passed to this callback, including Heartbeat Request and Heartbeat Response
	 * messages. However, responding to heartbeat is already done in osmo_pfcp_endpoint_handle_rx() before
	 * rx_msg_cb() is invoked: a callback implementation can safely ignore Heartbeat Request messages. */
	osmo_pfcp_endpoint_cb rx_msg_cb;

	/* Custom timer definitions to use, if any. Relevant timers are: OSMO_PFCP_TIMER_N1, OSMO_PFCP_TIMER_T1,
	 * OSMO_PFCP_TIMER_KEEP_RESP. These are used for the PFCP message retransmission queue.
	 * If passed NULL, use the timer definitions from the global osmo_pfcp_tdefs.
	 * To expose retransmission timers on the VTY configuration, it is convenient to add osmo_pfcp_tdefs as one of
	 * your program's osmo_tdef_group entries and call osmo_tdef_vty_init(). */
	const struct osmo_tdef *tdefs;

	/* application-private data */
	void *priv;

	/* Always false in this API version. When adding new members to this struct in the future, they shall be added
	 * after this 'more_items' flag, and such members shall be accessed only when more_items == true. */
	bool more_items;
};

struct osmo_pfcp_endpoint *osmo_pfcp_endpoint_create(void *ctx, const struct osmo_pfcp_endpoint_cfg *cfg);
int osmo_pfcp_endpoint_bind(struct osmo_pfcp_endpoint *ep);
void osmo_pfcp_endpoint_close(struct osmo_pfcp_endpoint *ep);
void osmo_pfcp_endpoint_free(struct osmo_pfcp_endpoint **ep);

int osmo_pfcp_endpoint_tx(struct osmo_pfcp_endpoint *ep, struct osmo_pfcp_msg *m);
int osmo_pfcp_endpoint_tx_data(struct osmo_pfcp_endpoint *ep, struct osmo_pfcp_msg *m);
int osmo_pfcp_endpoint_tx_heartbeat_req(struct osmo_pfcp_endpoint *ep, const struct osmo_sockaddr *remote_addr);

void osmo_pfcp_endpoint_invalidate_ctx(struct osmo_pfcp_endpoint *ep, struct osmo_fsm_inst *deleted_fi);

const struct osmo_pfcp_endpoint_cfg *osmo_pfcp_endpoint_get_cfg(const struct osmo_pfcp_endpoint *ep);
void *osmo_pfcp_endpoint_get_priv(const struct osmo_pfcp_endpoint *ep);
uint32_t osmo_pfcp_endpoint_get_recovery_timestamp(const struct osmo_pfcp_endpoint *ep);
const struct osmo_sockaddr *osmo_pfcp_endpoint_get_local_addr(const struct osmo_pfcp_endpoint *ep);
void osmo_pfcp_endpoint_set_seq_nr_state(struct osmo_pfcp_endpoint *ep, uint32_t seq_nr_state);

bool osmo_pfcp_endpoint_retrans_queue_is_busy(const struct osmo_pfcp_endpoint *ep);
