/* PFCP message encoding and decoding */
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
#include <inttypes.h>

#include <osmocom/core/socket.h>
#include <osmocom/core/msgb.h>
#include <osmocom/core/fsm.h>

#include <osmocom/pfcp/pfcp_proto.h>
#include <osmocom/pfcp/pfcp_ies_auto.h>
#include <osmocom/pfcp/pfcp_strs.h>

struct msgb;
struct osmo_t16l16v_ie;
struct osmo_pfcp_msg;

#define OSMO_PFCP_MSGB_ALLOC_SIZE 2048

#define OSMO_LOG_PFCP_MSG_SRC(M, LEVEL, file, line, FMT, ARGS...) \
	osmo_log_pfcp_msg_src(M, LEVEL, file, line, FMT, ##ARGS)

#define OSMO_LOG_PFCP_MSG(M, LEVEL, FMT, ARGS...) \
	OSMO_LOG_PFCP_MSG_SRC(M, LEVEL, __FILE__, __LINE__, FMT, ##ARGS)

struct osmo_pfcp_header_parsed {
	uint8_t version;
	enum osmo_pfcp_message_type message_type;
	uint32_t sequence_nr;
	bool priority_present;
	uint8_t priority;
	bool seid_present;
	uint64_t seid;
};

/* For PFCP requests, notify when a PFCP response has arrived, or when the PFCP response timed out.
 * When rx_resp == NULL, receiving a response timed out or the response could not be decoded.
 * On error, errmsg may convey a human readable error message.
 * Return 1 to also pass rx_resp to osmo_pfcp_endpoint->rx_msg(), return 0 to mark rx_resp handled and not pass it to
 * rx_msg() (to save lookup iterations). Return negative on error, rx_resp is dropped.
 * Find in req the original osmo_pfcp_msg instance; in req->ctx.priv, arbitrary user data may be passed.
 * For example:
 *
 *  static int on_foo_resp(struct osmo_pfcp_msg *req, struct osmo_pfcp_msg *rx_resp, const char *errmsg)
 *  {
 *          struct something *obj = req->ctx.priv;
 *          if (!rx_resp) {
 *                  handle_error();
 *                  return 0;
 *          }
 *          handle_response(obj, rx_resp);
 *          return 0;
 *  }
 *
 *  int do_request(struct something *obj)
 *  {
 *          struct osmo_pfcp_msg *req;
 *          req = osmo_pfcp_msg_alloc_tx(pfcp_ep, &upf_addr, &pfcp_ep->cfg.local_node_id, NULL, OSMO_PFCP_MSGT_FOO);
 *          req->h.seid_present = true;
 *          req->h.seid = remote_seid;
 *          req->ies.foo... = ...;
 *          req->ctx.on_resp = on_foo_resp;
 *          req->ctx.priv = obj;
 *          return osmo_pfcp_endpoint_tx(pfcp_ep, req);
 *  }
 */
typedef int (*osmo_pfcp_resp_cb)(struct osmo_pfcp_msg *req, struct osmo_pfcp_msg *rx_resp, const char *errmsg);

struct osmo_pfcp_msg {
	/* Peer's remote address. Received from this peer, or should be sent to this peer. */
	struct osmo_sockaddr remote_addr;
	/* True when this message was received from a remote; false when this message is going to be sent. */
	bool rx;
	/* True when this message is a Response message type; false if Request. This is set by
	 * osmo_pfcp_msg_decode() for received messages, and by osmo_pfcp_msg_alloc_tx */
	bool is_response;

	struct osmo_pfcp_header_parsed h;

	int ofs_cause;
	int ofs_node_id;

	/* The union of decoded IEs from all supported PFCP message types.  The union and its structure is defined in
	 * pfcp_ies_auto.h, which is generated by gen__pfcp_ies_auto.c.
	 */
	union osmo_pfcp_ies ies;

	/* Context information about this message, used for logging */
	struct {
		/* Peer FSM instance that this message is received from / sent to. This can be set in the
		 * osmo_pfcp_endpoint->set_msg_ctx() implementation, up to the caller. If present, this is used for
		 * logging context, and can also be used by the caller to reduce lookup iterations. */
		struct osmo_fsm_inst *peer_fi;
		struct osmo_use_count *peer_use_count;
		const char *peer_use_token;

		/* Session FSM instance that this message is received from / sent to. This can be set in the
		 * osmo_pfcp_endpoint->set_msg_ctx() implementation, up to the caller. If present, this is used for
		 * logging context, and can also be used by the caller to reduce lookup iterations. */
		struct osmo_fsm_inst *session_fi;
		struct osmo_use_count *session_use_count;
		const char *session_use_token;

		osmo_pfcp_resp_cb resp_cb;
		void *priv;
	} ctx;

	/* When a message gets encoded, the encoded packet is cached here for possible retransmissions. */
	struct msgb *encoded;
};

/* Given a &osmo_pfcp_msg->ies pointer, return the &osmo_pfcp_msg.
 * In the TLV API, only the 'ies' union is passed around as argument. This macro is useful in error callbacks to obtain
 * the related osmo_pfcp_msg and thus the logging context pointers (ctx.peer_fi and ctx.session_fi). */
#define OSMO_PFCP_MSG_FOR_IES(IES_P) ((struct osmo_pfcp_msg *)((char *)IES_P - offsetof(struct osmo_pfcp_msg, ies)))

bool osmo_pfcp_msgtype_is_response(enum osmo_pfcp_message_type message_type);

int osmo_pfcp_ie_f_teid_to_str_buf(char *buf, size_t len, const struct osmo_pfcp_ie_f_teid *ft);
char *osmo_pfcp_ie_f_teid_to_str_c(void *ctx, const struct osmo_pfcp_ie_f_teid *ft);

int osmo_pfcp_msg_encode(struct msgb *msg, const struct osmo_pfcp_msg *pfcp_msg);

int osmo_pfcp_msg_decode_header(struct osmo_gtlv_load *tlv, struct osmo_pfcp_msg *m,
				const struct msgb *msg);
int osmo_pfcp_msg_decode_tlv(struct osmo_pfcp_msg *m, struct osmo_gtlv_load *tlv);

struct osmo_pfcp_msg *osmo_pfcp_msg_alloc_rx(void *ctx, const struct osmo_sockaddr *remote_addr);
struct osmo_pfcp_msg *osmo_pfcp_msg_alloc_tx_req(void *ctx, const struct osmo_sockaddr *remote_addr,
						 enum osmo_pfcp_message_type msg_type);
struct osmo_pfcp_msg *osmo_pfcp_msg_alloc_tx_resp(void *ctx, const struct osmo_pfcp_msg *in_reply_to,
						  enum osmo_pfcp_message_type msg_type);

void osmo_pfcp_msg_invalidate_ctx(struct osmo_pfcp_msg *m, struct osmo_fsm_inst *deleted_fi);

void osmo_pfcp_msg_free(struct osmo_pfcp_msg *m);

uint32_t osmo_pfcp_next_seq_nr(uint32_t *next_seq_nr_state);
uint64_t osmo_pfcp_next_seid(uint64_t *next_seid_state);

int osmo_pfcp_ie_node_id_from_osmo_sockaddr(struct osmo_pfcp_ie_node_id *node_id, const struct osmo_sockaddr *os);
int osmo_pfcp_ie_node_id_to_osmo_sockaddr(const struct osmo_pfcp_ie_node_id *node_id, struct osmo_sockaddr *os);

#define OSMO_PFCP_MSG_MEMB(M, OFS) ((OFS) <= 0 ? NULL : (void *)((uint8_t *)(M) + OFS))

static inline enum osmo_pfcp_cause *osmo_pfcp_msg_cause(const struct osmo_pfcp_msg *m)
{
	return OSMO_PFCP_MSG_MEMB(m, m->ofs_cause);
}

static inline struct osmo_pfcp_ie_node_id *osmo_pfcp_msg_node_id(const struct osmo_pfcp_msg *m)
{
	return OSMO_PFCP_MSG_MEMB(m, m->ofs_node_id);
}

int osmo_pfcp_msg_to_str_buf(char *buf, size_t buflen, const struct osmo_pfcp_msg *m);
char *osmo_pfcp_msg_to_str_c(void *ctx, const struct osmo_pfcp_msg *m);

void osmo_log_pfcp_msg_src(const struct osmo_pfcp_msg *m, unsigned int level, const char *file, int line,
			   const char *fmt, ...);
