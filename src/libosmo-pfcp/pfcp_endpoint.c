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
#include <unistd.h>
#include <time.h>

#include <osmocom/core/talloc.h>
#include <osmocom/core/timer.h>
#include <osmocom/core/tdef.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/hashtable.h>
#include <osmocom/core/osmo_io.h>

#include <osmocom/pfcp/pfcp_endpoint.h>
#include <osmocom/pfcp/pfcp_msg.h>

/* Send/receive PFCP messages to/from remote PFCP endpoints. */
struct osmo_pfcp_endpoint {
	struct osmo_pfcp_endpoint_cfg cfg;

	/* PFCP socket */
	struct osmo_io_fd *iofd;

	/* The time at which this endpoint last restarted, as seconds since unix epoch. */
	uint32_t recovery_time_stamp;

	/* State for determining the next sequence number for transmitting a request message */
	uint32_t seq_nr_state;

	/* All transmitted PFCP Request messages, list of osmo_pfcp_queue_entry.
	 * For a transmitted Request message, wait for a matching Response from a remote peer; if none arrives,
	 * retransmit (see n1 and t1_ms). */
	struct llist_head sent_requests;
	DECLARE_HASHTABLE(sent_requests_by_seq_nr, 12);
	/* All transmitted PFCP Response messages, list of osmo_pfcp_queue_entry.
	 * For a transmitted Response message, keep it in the queue for a fixed amount of time. If the peer retransmits
	 * the original Request, do not dispatch the Request, but respond with the queued message directly. */
	struct llist_head sent_responses;
	DECLARE_HASHTABLE(sent_responses_by_seq_nr, 12);
};

/*! Entry of pfcp_endpoint message queue of PFCP messages, for re-transsions. */
struct osmo_pfcp_queue_entry {
	/* entry in osmo_pfcp_endpoint.sent_requests or .sent_responses */
	struct llist_head entry;
	 /* item in osmo_pfcp_endpoint's sent_responses_by_seq_nr or sent_responses_by_seq_nr */
	struct hlist_node node_by_seq_nr;
	/* back-pointer */
	struct osmo_pfcp_endpoint *ep;
	/* message we have transmitted */
	struct osmo_pfcp_msg *m;
	/* T1 timer: wait for response before retransmitting request / keep response in case the same request is
	 * received again. */
	struct osmo_timer_list t1;
	/* N1: number of pending re-transmissions */
	unsigned int n1_remaining;
};

/* clean up and deallocate the given osmo_pfcp_queue_entry */
static void osmo_pfcp_queue_del(struct osmo_pfcp_queue_entry *qe)
{
	/* see also the talloc destructor: osmo_pfcp_queue_destructor() */
	talloc_free(qe);
}

static int osmo_pfcp_queue_destructor(struct osmo_pfcp_queue_entry *qe)
{
	osmo_timer_del(&qe->t1);
	hash_del(&qe->node_by_seq_nr);
	llist_del(&qe->entry);
	return 0;
}

/* Global timer definitions for PFCP operation, provided for convenience. A caller of the PFCP API may decide to use
 * these in osmo_pfcp_endpoint and own FSM implementations. To make these user configurable, it is convenient to add
 * osmo_pfcp_tdefs as one of your program's osmo_tdef_group entries and call osmo_tdef_vty_init(). */
struct osmo_tdef osmo_pfcp_tdefs[] = {
	{ .T = OSMO_PFCP_TIMER_HEARTBEAT_REQ, .default_val = 15, .unit = OSMO_TDEF_S,
	  .desc = "PFCP Heartbeat Request period, how long to wait between issuing requests"
	},
	{ .T = OSMO_PFCP_TIMER_HEARTBEAT_RESP, .default_val = 15, .unit = OSMO_TDEF_S,
	  .desc = "PFCP Heartbeat Response timeout, the time after which to regard a non-responding peer as disconnected"
	},
	{ .T = OSMO_PFCP_TIMER_GRACEFUL_REL, .default_val = 15, .unit = OSMO_TDEF_S,
	  .desc = "PFCP peer graceful shutdown timeout, how long to keep the peer's state after a peer requested"
		  " graceful shutdown"
	},
	{ .T = OSMO_PFCP_TIMER_T1, .default_val = 3000, .unit = OSMO_TDEF_MS,
	  .desc = "PFCP request timeout, how long after a missing response to retransmit a PFCP request"
	},
	{ .T = OSMO_PFCP_TIMER_N1, .default_val = 3, .unit = OSMO_TDEF_CUSTOM,
	  .desc = "Number of PFCP request retransmission attempts"
	},
	{ .T = OSMO_PFCP_TIMER_KEEP_RESP, .default_val = 10000, .unit = OSMO_TDEF_MS,
	  .desc = "PFCP response timeout, how long to keep a response, in case its same request is retransmitted by the peer"
	},
	{ .T = OSMO_PFCP_TIMER_ASSOC_RETRY, .default_val = 15, .unit = OSMO_TDEF_S,
	  .desc = "Idle time between attempts of PFCP Association Setup (CPF)"
	},
	{}
};

/* Allocate a PFCP endpoint. Copy cfg's content to the allocated endpoint struct. Set the recovery_time_stamp to the
 * current time. */
struct osmo_pfcp_endpoint *osmo_pfcp_endpoint_create(void *ctx, const struct osmo_pfcp_endpoint_cfg *cfg)
{
	struct osmo_pfcp_endpoint *ep = talloc_zero(ctx, struct osmo_pfcp_endpoint);
	uint32_t unix_time;
	if (!ep)
		return NULL;

	ep->cfg = *cfg;
	if (!ep->cfg.tdefs)
		ep->cfg.tdefs = osmo_pfcp_tdefs;

	INIT_LLIST_HEAD(&ep->sent_requests);
	INIT_LLIST_HEAD(&ep->sent_responses);
	hash_init(ep->sent_requests_by_seq_nr);
	hash_init(ep->sent_responses_by_seq_nr);

	/* time() returns seconds since 1970 (UNIX epoch), but the recovery_time_stamp is coded in the NTP format, which is
	 * seconds since 1900, the NTP era 0. 2208988800L is the offset between UNIX epoch and NTP era 0.
	 * TODO: what happens when we enter NTP era 1? Is it sufficient to integer-wrap? */
	unix_time = time(NULL);
	ep->recovery_time_stamp = unix_time + 2208988800L;
	LOGP(DLPFCP, LOGL_NOTICE, "PFCP endpoint: recovery timestamp = 0x%08x (%u seconds since UNIX epoch,"
	     " which is %u seconds since NTP era 0; IETF RFC 5905)\n",
	     ep->recovery_time_stamp, unix_time, ep->recovery_time_stamp);

	return ep;
}

static unsigned int ep_n1(struct osmo_pfcp_endpoint *ep)
{
	return osmo_tdef_get(ep->cfg.tdefs, OSMO_PFCP_TIMER_N1, OSMO_TDEF_CUSTOM, -1);
}

static unsigned int ep_t1(struct osmo_pfcp_endpoint *ep)
{
	return osmo_tdef_get(ep->cfg.tdefs, OSMO_PFCP_TIMER_T1, OSMO_TDEF_MS, -1);
}

static unsigned int ep_keep_resp(const struct osmo_pfcp_endpoint *ep, const struct osmo_pfcp_msg *m)
{
	/* Don't check for PFCP Assoc Setup Req duplicates: There's no way to
	 * differentiate a duplicate from a new instance of a CP peer which chooses
	 * (willingly or randomly) after restart the same Sequence Number as in previous run. */
	if (m->h.message_type == OSMO_PFCP_MSGT_ASSOC_SETUP_REQ)
		return 0;
	return osmo_tdef_get(ep->cfg.tdefs, OSMO_PFCP_TIMER_KEEP_RESP, OSMO_TDEF_MS, -1);
}

static int osmo_pfcp_endpoint_tx_data_no_logging(struct osmo_pfcp_endpoint *ep, struct osmo_pfcp_msg *m);

/* Return true to keep the message in the queue, false for dropping from the queue. */
static bool pfcp_queue_retrans(struct osmo_pfcp_queue_entry *qe)
{
	struct osmo_pfcp_endpoint *endpoint = qe->ep;
	unsigned int t1_ms = ep_t1(endpoint);
	struct osmo_pfcp_msg *m = qe->m;
	int rc;

	/* if no more attempts remaining, drop from queue */
	if (!qe->n1_remaining)
		return false;

	/* re-transmit */
	qe->n1_remaining--;
	OSMO_LOG_PFCP_MSG(m, LOGL_INFO, "re-sending (%u attempts remaining after this)\n", qe->n1_remaining);

	rc = osmo_pfcp_endpoint_tx_data_no_logging(endpoint, m);
	/* If encoding failed, it cannot ever succeed. Drop the queue entry. (Error logging already taken care of in
	 * osmo_pfcp_endpoint_tx_data_no_logging().) */
	if (rc)
		return false;
	/* re-schedule timer, keep in queue */
	osmo_timer_schedule(&qe->t1, t1_ms/1000, (t1_ms % 1000) * 1000);
	return true;
}

/* T1 for a given sent_requests queue entry has expired */
static void pfcp_queue_sent_req_timer_cb(void *data)
{
	struct osmo_pfcp_queue_entry *qe = data;
	bool keep;

	/* qe->m is a request sent earlier */
	OSMO_ASSERT(!qe->m->is_response);

	/* The request is still here, which means it has not received a response from the remote side.
	 * Retransmit the request. */
	keep = pfcp_queue_retrans(qe);
	if (keep)
		return;

	/* Retransmission has elapsed. Notify resp_cb that receiving a response has failed. */
	if (qe->m->ctx.resp_cb)
		qe->m->ctx.resp_cb(qe->m, NULL, "PFCP request retransmissions elapsed, no response received");
	/* Drop the queue entry. No more retransmissions. */
	osmo_pfcp_queue_del(qe);
}

/* T1 for a given sent_responses queue entry has expired */
static void pfcp_queue_sent_resp_timer_cb(void *data)
{
	struct osmo_pfcp_queue_entry *qe = data;

	/* qe->m is a response sent earlier */
	OSMO_ASSERT(qe->m->is_response);

	/* The response has waited in the queue for any retransmissions of its initiating request. Now that time
	 * has passed and the response can be dropped from the queue. */
	osmo_pfcp_queue_del(qe);
}

/* Directly encode and transmit the message, without storing in the retrans_queue. */
static int osmo_pfcp_endpoint_tx_data_no_logging(struct osmo_pfcp_endpoint *ep, struct osmo_pfcp_msg *m)
{
	struct msgb *msg;
	int rc;

	msg = msgb_alloc_c(ep->iofd, OSMO_PFCP_MSGB_ALLOC_SIZE, "PFCP-tx");
	OSMO_ASSERT(msg);

	rc = osmo_pfcp_msg_encode(msg, m);
	if (rc) {
		msgb_free(msg);
		return rc;
	}

	rc = osmo_iofd_sendto_msgb(ep->iofd, msg, 0, &m->remote_addr);
	if (rc < 0) {
		OSMO_LOG_PFCP_MSG(m, LOGL_ERROR, "sendto() failed: rc = %d\n", rc);
		msgb_free(msg);
		return -EIO;
	}
	return 0;
}

int osmo_pfcp_endpoint_tx_data(struct osmo_pfcp_endpoint *ep, struct osmo_pfcp_msg *m)
{
	OSMO_LOG_PFCP_MSG(m, LOGL_INFO, "sending\n");
	return osmo_pfcp_endpoint_tx_data_no_logging(ep, m);
}

int osmo_pfcp_endpoint_tx_heartbeat_req(struct osmo_pfcp_endpoint *ep, const struct osmo_sockaddr *remote_addr)
{
	struct osmo_pfcp_msg *tx = osmo_pfcp_msg_alloc_tx_req(OTC_SELECT, remote_addr, OSMO_PFCP_MSGT_HEARTBEAT_REQ);
	tx->ies.heartbeat_req.recovery_time_stamp = ep->recovery_time_stamp;
	tx->h.sequence_nr = osmo_pfcp_next_seq_nr(&ep->seq_nr_state);
	return osmo_pfcp_endpoint_tx_data(ep, tx);
}

/* add a given msgb to the queue of per-peer messages waiting for a response */
static int osmo_pfcp_endpoint_retrans_queue_add(struct osmo_pfcp_endpoint *endpoint, struct osmo_pfcp_msg *m)
{
	struct osmo_pfcp_queue_entry *qe;
	unsigned int timeout_ms;
	unsigned int n1 = 0;

	if (m->is_response) {
		timeout_ms = ep_keep_resp(endpoint, m);
		OSMO_LOG_PFCP_MSG(m, LOGL_DEBUG, "keep sent Responses for %ums\n", timeout_ms);
	} else {
		timeout_ms = ep_t1(endpoint);
		n1 = ep_n1(endpoint);

		OSMO_LOG_PFCP_MSG(m, LOGL_DEBUG, "retransmit unanswered Requests %u x %ums\n", n1, timeout_ms);
		/* If there are no retransmissions or no timeout, it makes no sense to add to the queue. */
		if (!n1 || !timeout_ms) {
			if (!m->is_response && m->ctx.resp_cb)
				m->ctx.resp_cb(m, NULL, "PFCP timeout is zero, cannot wait for a response");
			return 0;
		}
	}

	qe = talloc(endpoint, struct osmo_pfcp_queue_entry);
	OSMO_ASSERT(qe);
	*qe = (struct osmo_pfcp_queue_entry){
		.ep = endpoint,
		.m = m,
		.n1_remaining = n1,
	};
	talloc_steal(qe, m);

	/* Slight optimization: Add sent requests to the start of the list: we will usually receive a response shortly
	 * after sending a request, removing that entry from the queue quickly.
	 * Add sent responses to the end of the list: they will rarely be retransmitted at all. */
	if (m->is_response) {
		llist_add_tail(&qe->entry, &endpoint->sent_responses);
		hash_add(endpoint->sent_responses_by_seq_nr, &qe->node_by_seq_nr, m->h.sequence_nr);
		osmo_timer_setup(&qe->t1, pfcp_queue_sent_resp_timer_cb, qe);
	} else {
		llist_add(&qe->entry, &endpoint->sent_requests);
		hash_add(endpoint->sent_requests_by_seq_nr, &qe->node_by_seq_nr, m->h.sequence_nr);
		osmo_timer_setup(&qe->t1, pfcp_queue_sent_req_timer_cb, qe);
	}
	talloc_set_destructor(qe, osmo_pfcp_queue_destructor);

	osmo_timer_schedule(&qe->t1, timeout_ms/1000, (timeout_ms % 1000) * 1000);
	return 0;
}

/* Transmit a PFCP message.
 * Store the message in the local message queue for possible retransmissions.
 * On success, return zero, and pass ownership of m to ep. ep deallocates m when all retransmissions are done / a reply
 * has been received.
 * On error, return nonzero, and immediately deallocate m.
 *
 * WARNING: Do not access the osmo_pfcp_msg m after calling this function! In most cases, m will still remain allocated,
 * and accessing it will work, but especially when an error occurs, m will be deallocated immediately. Hence, you will
 * see no problem during normal successful operation, but your program will crash with use-after-free on any error!
 */
int osmo_pfcp_endpoint_tx(struct osmo_pfcp_endpoint *ep, struct osmo_pfcp_msg *m)
{
	struct osmo_pfcp_ie_node_id *node_id;
	int rc;
	if (!m->is_response)
		m->h.sequence_nr = osmo_pfcp_next_seq_nr(&ep->seq_nr_state);
	node_id = osmo_pfcp_msg_node_id(m);
	if (node_id)
		*node_id = ep->cfg.local_node_id;

	rc = osmo_pfcp_endpoint_tx_data(ep, m);
	if (rc) {
		if (!m->is_response && m->ctx.resp_cb)
			m->ctx.resp_cb(m, NULL, "Failed to transmit request");
		osmo_pfcp_msg_free(m);
		return rc;
	}
	osmo_pfcp_endpoint_retrans_queue_add(ep, m);
	return 0;
}

static struct osmo_pfcp_queue_entry *osmo_pfcp_enfpoint_find_sent_request(const struct osmo_pfcp_endpoint *ep, uint32_t seq_nr)
{
	struct osmo_pfcp_queue_entry *qe;
	hash_for_each_possible(ep->sent_requests_by_seq_nr, qe, node_by_seq_nr, seq_nr) {
		OSMO_ASSERT(qe->m);
		if (qe->m->h.sequence_nr != seq_nr)
			continue;
		return qe;
	}
	return NULL;
}

static struct osmo_pfcp_queue_entry *osmo_pfcp_enfpoint_find_sent_response(const struct osmo_pfcp_endpoint *ep, uint32_t seq_nr)
{
	struct osmo_pfcp_queue_entry *qe;
	hash_for_each_possible(ep->sent_responses_by_seq_nr, qe, node_by_seq_nr, seq_nr) {
		OSMO_ASSERT(qe->m);
		if (qe->m->h.sequence_nr != seq_nr)
			continue;
		return qe;
	}
	return NULL;
}

static void osmo_pfcp_endpoint_handle_rx(struct osmo_pfcp_endpoint *ep, struct osmo_pfcp_msg *m)
{
	bool dispatch_rx = true;
	struct osmo_pfcp_queue_entry *prev_msg;
	struct osmo_pfcp_msg *req;

	if (m->h.message_type == OSMO_PFCP_MSGT_HEARTBEAT_REQ) {
		/* Directly answer with a Heartbeat Response. */
		struct osmo_pfcp_msg *resp = osmo_pfcp_msg_alloc_tx_resp(OTC_SELECT, m, OSMO_PFCP_MSGT_HEARTBEAT_RESP);
		resp->ies.heartbeat_resp.recovery_time_stamp = ep->recovery_time_stamp;
		osmo_pfcp_endpoint_tx_data(ep, resp);
		/* Still also dispatch the Rx event to the peer. */
	}

	/* If this is receiving a response, search for matching sent request that is now completed.
	 * If this is receiving a request, search for a matching sent response that can be retransmitted.
	 * A match is found by sequence_nr. */
	if (m->is_response)
		prev_msg = osmo_pfcp_enfpoint_find_sent_request(ep, m->h.sequence_nr);
	else
		prev_msg = osmo_pfcp_enfpoint_find_sent_response(ep, m->h.sequence_nr);

	if (prev_msg && !m->is_response) {
		/* m is a request, and we have already sent a response to this same request earlier. Retransmit the same
		 * response, and don't dispatch the msg rx. Keep our response queued in case the request is
		 * retransmitted yet another time. */

		/* Populate message context to point at peer and session, if applicable.
		 * With that context applied, log message rx. */
		if (ep->cfg.set_msg_ctx_cb)
			ep->cfg.set_msg_ctx_cb(ep, m, NULL);
		OSMO_LOG_PFCP_MSG(m, LOGL_INFO, "received retransmission of earlier request\n");

		/* Also log on the earlier PFCP msg that it is resent */
		OSMO_LOG_PFCP_MSG(prev_msg->m, LOGL_INFO, "re-sending cached response\n");
		osmo_pfcp_endpoint_tx_data_no_logging(ep, prev_msg->m);
		return;
	}

	req = NULL;
	if (prev_msg && m->is_response) {
		/* m is a response to the earlier request prev_msg->m. The request is now ACKed and can be dropped from
		 * the retransmission queue: see 'if (req)' below. */
		req = prev_msg->m;
	}

	/* Populate message context to point at peer and session, if applicable.
	 * With that context applied, log message rx. */
	if (ep->cfg.set_msg_ctx_cb)
		ep->cfg.set_msg_ctx_cb(ep, m, req);
	OSMO_LOG_PFCP_MSG(m, LOGL_INFO, "received\n");

	if (req && req->ctx.resp_cb) {
		int rc = req->ctx.resp_cb(req, m, NULL);
		/* Only dispatch the response to rx_msg() when resp_cb() asks for it with rc == 1 (or when there is no
		 * resp_cb()). */
		if (rc != 1) {
			dispatch_rx = false;
			OSMO_LOG_PFCP_MSG(m, LOGL_DEBUG,
					  "response handled by m->resp_cb(), not dispatching to rx_msg_cb()\n");
		}
	}

	if (dispatch_rx)
		ep->cfg.rx_msg_cb(ep, m, req);
	if (req)
		osmo_pfcp_queue_del(prev_msg);
}

/* call-back for PFCP socket file descriptor */
static void osmo_pfcp_iofd_sendto_cb(struct osmo_io_fd *iofd, int res, struct msgb *msg,
				     const struct osmo_sockaddr *daddr)
{
	if (OSMO_UNLIKELY(res <= 0)) {
		char addrbuf[INET6_ADDRSTRLEN];
		LOGP(DLPFCP, LOGL_ERROR, "PFCP Tx to %s returned %d!\n",
		     osmo_sockaddr_to_str_buf(addrbuf, sizeof(addrbuf), daddr), res);
	}
}

static void osmo_pfcp_iofd_recvfrom_cb(struct osmo_io_fd *iofd, int res, struct msgb *msg,
				      const struct osmo_sockaddr *saddr)
{
	int rc;
	struct osmo_pfcp_endpoint *ep = osmo_iofd_get_data(iofd);

	if (OSMO_UNLIKELY(res <= 0)) {
		char addrbuf[INET6_ADDRSTRLEN];
		LOGP(DLPFCP, LOGL_ERROR, "PFCP Rx from %s returned %d!\n",
		     osmo_sockaddr_to_str_buf(addrbuf, sizeof(addrbuf), saddr), res);
		return;
	}

	if (!msg)
		return;

	msg->l3h = msgb_data(msg);

	OSMO_ASSERT(ep->cfg.rx_msg_cb);

	/* This may be a bundle of PFCP messages. Parse and receive each message received, by shifting l4h
	 * through the message bundle. */
	msg->l4h = msg->l3h;
	while (msgb_l4len(msg)) {
		struct osmo_gtlv_load tlv;
		struct osmo_pfcp_msg *m = osmo_pfcp_msg_alloc_rx(OTC_SELECT, saddr);
		m->encoded = msg;

		rc = osmo_pfcp_msg_decode_header(&tlv, m, msg);
		if (rc < 0)
			break;
		msg->l4h += rc;

		rc = osmo_pfcp_msg_decode_tlv(m, &tlv);
		/* If errors occurred, they have already been logged on DLPFCP. */
		if (rc == 0)
			osmo_pfcp_endpoint_handle_rx(ep, m);
		osmo_pfcp_msg_free(m);
	}
	msgb_free(msg);
}

static const struct osmo_io_ops ioops = {
	.sendto_cb = &osmo_pfcp_iofd_sendto_cb,
	.recvfrom_cb = &osmo_pfcp_iofd_recvfrom_cb,
};

/*! bind a PFCP endpoint to its configured address (ep->cfg.local_addr).
 * \return 0 on success, negative on error. */
int osmo_pfcp_endpoint_bind(struct osmo_pfcp_endpoint *ep)
{
	int rc;
	/* close the existing socket, if any */
	osmo_pfcp_endpoint_close(ep);

	if (!ep->cfg.rx_msg_cb) {
		LOGP(DLPFCP, LOGL_ERROR, "missing cfg.rx_msg_cb at osmo_pfcp_endpoint\n");
		return -EINVAL;
	}

	/* create the new socket, binding to configured local address */
	rc = osmo_sock_init_osa(SOCK_DGRAM, IPPROTO_UDP, &ep->cfg.local_addr, NULL, OSMO_SOCK_F_BIND);
	if (rc < 0)
		return rc;

	ep->iofd = osmo_iofd_setup(ep, rc, "pfcp", OSMO_IO_FD_MODE_RECVFROM_SENDTO, &ioops, ep);
	if (!ep->iofd) {
		close(rc);
		return -EIO;
	}
	osmo_iofd_set_alloc_info(ep->iofd, OSMO_PFCP_MSGB_ALLOC_SIZE, 0);

	rc = osmo_iofd_register(ep->iofd, -1);
	if (rc < 0) {
		osmo_iofd_free(ep->iofd);
		ep->iofd = NULL;
		return rc;
	}
	return 0;
}

void osmo_pfcp_endpoint_close(struct osmo_pfcp_endpoint *ep)
{
	struct osmo_pfcp_queue_entry *qe;
	while ((qe = llist_first_entry_or_null(&ep->sent_requests, struct osmo_pfcp_queue_entry, entry)))
		osmo_pfcp_queue_del(qe);
	while ((qe = llist_first_entry_or_null(&ep->sent_responses, struct osmo_pfcp_queue_entry, entry)))
		osmo_pfcp_queue_del(qe);

	osmo_iofd_free(ep->iofd);
	ep->iofd = NULL;
}

void osmo_pfcp_endpoint_free(struct osmo_pfcp_endpoint **ep)
{
	if (!*ep)
		return;
	osmo_pfcp_endpoint_close(*ep);
	talloc_free(*ep);
	*ep = NULL;
}

/* Call osmo_pfcp_msg_invalidate_ctx(deleted_fi) on all queued osmo_pfcp_msg instances in the retrans_queue. */
void osmo_pfcp_endpoint_invalidate_ctx(struct osmo_pfcp_endpoint *ep, struct osmo_fsm_inst *deleted_fi)
{
	struct osmo_pfcp_queue_entry *qe;
	llist_for_each_entry(qe, &ep->sent_requests, entry)
		osmo_pfcp_msg_invalidate_ctx(qe->m, deleted_fi);
	llist_for_each_entry(qe, &ep->sent_responses, entry)
		osmo_pfcp_msg_invalidate_ctx(qe->m, deleted_fi);
}

/* Return the cfg for an endpoint, guaranteed to return non-NULL for a valid ep. */
const struct osmo_pfcp_endpoint_cfg *osmo_pfcp_endpoint_get_cfg(const struct osmo_pfcp_endpoint *ep)
{
	return &ep->cfg;
}

/* Shorthand for &osmo_pfcp_endpoint_get_cfg(ep)->priv */
void *osmo_pfcp_endpoint_get_priv(const struct osmo_pfcp_endpoint *ep)
{
	return ep->cfg.priv;
}

uint32_t osmo_pfcp_endpoint_get_recovery_timestamp(const struct osmo_pfcp_endpoint *ep)
{
	return ep->recovery_time_stamp;
}

/* Shorthand for &osmo_pfcp_endpoint_get_cfg(ep)->local_addr */
const struct osmo_sockaddr *osmo_pfcp_endpoint_get_local_addr(const struct osmo_pfcp_endpoint *ep)
{
	return &ep->cfg.local_addr;
}

void osmo_pfcp_endpoint_set_seq_nr_state(struct osmo_pfcp_endpoint *ep, uint32_t seq_nr_state)
{
	ep->seq_nr_state = seq_nr_state;
}

/* Return true when the retransmission queues contain any PFCP messages, false when the queues are empty. */
bool osmo_pfcp_endpoint_retrans_queue_is_busy(const struct osmo_pfcp_endpoint *ep)
{
	return !(llist_empty(&ep->sent_requests) && llist_empty(&ep->sent_responses));
}
