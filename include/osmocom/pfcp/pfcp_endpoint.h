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

#define OSMO_PFCP_TIMER_HEARTBEAT_REQ -19
#define OSMO_PFCP_TIMER_HEARTBEAT_RESP -20
#define OSMO_PFCP_TIMER_GRACEFUL_REL -21
#define OSMO_PFCP_TIMER_T1 -22
#define OSMO_PFCP_TIMER_N1 -23
#define OSMO_PFCP_TIMER_KEEP_RESP -24
#define OSMO_PFCP_TIMER_ASSOC_RETRY -26

extern struct osmo_tdef osmo_pfcp_tdefs[];

/* Ownership of m remains with the caller / m will be deallocated by the caller.
 * \param ep  The PFCP endpoint that received and decoded the message.
 * \param m  The message that was received.
 * \param req  If m is a PFCP Response to an earlier Request, req is that request message. Otherwise req is NULL.
 */
typedef void (*osmo_pfcp_endpoint_cb)(struct osmo_pfcp_endpoint *ep, struct osmo_pfcp_msg *m,
				      struct osmo_pfcp_msg *req);

/* Send/receive PFCP messages to/from remote PFCP endpoints. */
struct osmo_pfcp_endpoint {
	struct {
		/* Local address */
		struct osmo_sockaddr local_addr;
		/* Local PFCP Node ID, as sent in outgoing messages' Node ID IE */
		struct osmo_pfcp_ie_node_id local_node_id;

		/* Timer definitions to use, if any. See t1_ms, keep_resp_ms. Use osmo_pfcp_tdefs by default. It is
		 * convenient to add osmo_pfcp_tdefs as one of your program's osmo_tdef_group entries and call
		 * osmo_tdef_vty_init() to expose PFCP timers on the VTY. */
		const struct osmo_tdef *tdefs;
	} cfg;

	/* PFCP socket */
	struct osmo_fd pfcp_fd;

	/* The time at which this endpoint last restarted, as seconds since unix epoch. */
	uint32_t recovery_time_stamp;

	/* State for determining the next sequence number for transmitting a request message */
	uint32_t seq_nr_state;

	/* This function is called just after decoding and before handling the message.
	 * This function may set ctx.peer_fi and ctx.session_fi, used for logging context during message decoding.
	 * The caller may also use these fi pointers to reduce lookup iterations in rx_msg().
	 */
	osmo_pfcp_endpoint_cb set_msg_ctx;

	/* Callback to receive single incoming PFCP messages from a remote peer, already decoded. */
	osmo_pfcp_endpoint_cb rx_msg;

	/* application-private data */
	void *priv;

	/* All transmitted PFCP Request messages, list of osmo_pfcp_queue_entry.
	 * For a transmitted Request message, wait for a matching Response from a remote peer; if none arrives,
	 * retransmit (see n1 and t1_ms). */
	struct llist_head sent_requests;
	/* All transmitted PFCP Response messages, list of osmo_pfcp_queue_entry.
	 * For a transmitted Response message, keep it in the queue for a fixed amount of time. If the peer retransmits
	 * the original Request, do not dispatch the Request, but respond with the queued message directly. */
	struct llist_head sent_responses;
};

struct osmo_pfcp_endpoint *osmo_pfcp_endpoint_create(void *ctx, void *priv);
int osmo_pfcp_endpoint_bind(struct osmo_pfcp_endpoint *ep);
void osmo_pfcp_endpoint_close(struct osmo_pfcp_endpoint *ep);
void osmo_pfcp_endpoint_free(struct osmo_pfcp_endpoint **ep);

int osmo_pfcp_endpoint_tx(struct osmo_pfcp_endpoint *ep, struct osmo_pfcp_msg *m);
int osmo_pfcp_endpoint_tx_data(struct osmo_pfcp_endpoint *ep, struct osmo_pfcp_msg *m);
int osmo_pfcp_endpoint_tx_heartbeat_req(struct osmo_pfcp_endpoint *ep, const struct osmo_sockaddr *remote_addr);

void osmo_pfcp_endpoint_invalidate_ctx(struct osmo_pfcp_endpoint *ep, struct osmo_fsm_inst *deleted_fi);
