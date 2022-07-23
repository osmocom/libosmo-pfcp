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

#include <osmocom/core/utils.h>
#include <osmocom/core/fsm.h>
#include <osmocom/core/tdef.h>

#include <osmocom/pfcp/pfcp_endpoint.h>
#include <osmocom/pfcp/pfcp_cp_peer.h>

#define LOG_CP_PEER(CP_PEER, LOGLEVEL, FMT, ARGS...) \
	LOGPFSML((CP_PEER)->fi, LOGLEVEL, FMT, ##ARGS)

enum pfcp_cp_peer_fsm_state {
	PFCP_CP_PEER_ST_DISABLED,
	PFCP_CP_PEER_ST_WAIT_ASSOC_SETUP_RESP,
	PFCP_CP_PEER_ST_WAIT_RETRY,
	PFCP_CP_PEER_ST_ASSOCIATED,
	PFCP_CP_PEER_ST_GRACEFUL_RELEASE,
	PFCP_CP_PEER_ST_WAIT_USE_COUNT,
};

enum pfcp_cp_peer_fsm_event {
	PFCP_CP_PEER_EV_RX_ASSOC_SETUP_RESP,
	PFCP_CP_PEER_EV_RX_ASSOC_UPDATE_REQ,
	PFCP_CP_PEER_EV_USE_COUNT_ZERO,
};

static const struct value_string pfcp_cp_peer_fsm_event_names[] = {
	OSMO_VALUE_STRING(PFCP_CP_PEER_EV_RX_ASSOC_SETUP_RESP),
	OSMO_VALUE_STRING(PFCP_CP_PEER_EV_RX_ASSOC_UPDATE_REQ),
	OSMO_VALUE_STRING(PFCP_CP_PEER_EV_USE_COUNT_ZERO),
	{}
};

static struct osmo_fsm pfcp_cp_peer_fsm;

static const struct osmo_tdef_state_timeout pfcp_cp_peer_fsm_timeouts[32] = {
	[PFCP_CP_PEER_ST_WAIT_RETRY] = { .T = -26 },
	/* PFCP_CP_PEER_ST_WAIT_ASSOC_SETUP_RESP is terminated by the on_pfcp_assoc_resp() callback */
	[PFCP_CP_PEER_ST_GRACEFUL_RELEASE] = { .T = -21 },
};

/* Transition to a state, using the T timer defined in pfcp_cp_peer_fsm_timeouts.
 * Assumes local variable fi exists. */
#define osmo_pfcp_cp_peer_fsm_state_chg(state) \
       osmo_tdef_fsm_inst_state_chg(fi, state, \
				    pfcp_cp_peer_fsm_timeouts, \
				    osmo_pfcp_tdefs, \
				    5)

static int pfcp_cp_peer_use_cb(struct osmo_use_count_entry *e, int32_t old_use_count, const char *file, int line)
{
	struct osmo_pfcp_cp_peer *cp_peer = e->use_count->talloc_object;

	if (!e->use)
		return -EINVAL;

	LOGPFSMSLSRC(cp_peer->fi, DLPFCP, LOGL_DEBUG, file, line,
		     "%s %s: now used by %s\n",
		     e->count > old_use_count ? "+" : "-", e->use,
		     osmo_use_count_to_str_c(OTC_SELECT, &cp_peer->use_count));

	if (e->count < 0)
		return -ERANGE;

	if (osmo_use_count_total(&cp_peer->use_count) == 0)
		osmo_fsm_inst_dispatch(cp_peer->fi, PFCP_CP_PEER_EV_USE_COUNT_ZERO, NULL);
	return 0;
}

/* Allocate PFCP CP peer FSM and start sending PFCP Association Setup Request messages to remote_addr, using endpoint
 * ep. As soon as a successful response is received, change to state PFCP_CP_PEER_ST_ASSOCIATED.
 */
struct osmo_pfcp_cp_peer *osmo_pfcp_cp_peer_alloc(void *ctx,
						  struct osmo_pfcp_endpoint *ep,
						  const struct osmo_sockaddr *remote_addr)
{
	struct osmo_pfcp_cp_peer *cp_peer;
	struct osmo_fsm_inst *fi = osmo_fsm_inst_alloc(&pfcp_cp_peer_fsm, ctx, NULL, LOGL_DEBUG, NULL);
	OSMO_ASSERT(fi);

	cp_peer = talloc(fi, struct osmo_pfcp_cp_peer);
	OSMO_ASSERT(cp_peer);
	fi->priv = cp_peer;
	*cp_peer = (struct osmo_pfcp_cp_peer){
		.fi = fi,
		.ep = ep,
		.remote_addr = *remote_addr,
		.use_count = {
			.talloc_object = cp_peer,
			.use_cb = pfcp_cp_peer_use_cb,
		},
	};
	osmo_use_count_make_static_entries(&cp_peer->use_count, cp_peer->use_count_buf, ARRAY_SIZE(cp_peer->use_count_buf));

	osmo_fsm_inst_update_id_f_sanitize(fi, '-', osmo_sockaddr_to_str_c(OTC_SELECT, &cp_peer->remote_addr));
	return cp_peer;
}

int osmo_pfcp_cp_peer_associate(struct osmo_pfcp_cp_peer *cp_peer)
{
	struct osmo_fsm_inst *fi = cp_peer->fi;

	switch (fi->state) {
	case PFCP_CP_PEER_ST_DISABLED:
	case PFCP_CP_PEER_ST_WAIT_RETRY:
		/* Idling. Send Association Setup Request now. */
		return osmo_pfcp_cp_peer_fsm_state_chg(PFCP_CP_PEER_ST_WAIT_ASSOC_SETUP_RESP);
	default:
		/* Already associated, or busy associating. */
		return 0;
	case PFCP_CP_PEER_ST_WAIT_USE_COUNT:
		/* Already asked to deallocate. */
		return -ENOLINK;
	}
	return 0;
}

static int pfcp_cp_peer_fsm_timer_cb(struct osmo_fsm_inst *fi)
{
	switch (fi->state) {

	case PFCP_CP_PEER_ST_WAIT_RETRY:
		osmo_pfcp_cp_peer_fsm_state_chg(PFCP_CP_PEER_ST_WAIT_ASSOC_SETUP_RESP);
		return 0;

	default:
		return 1;
	}
}

static int on_pfcp_assoc_resp(struct osmo_pfcp_msg *req, struct osmo_pfcp_msg *rx_resp, const char *errmsg);

/* Send PFCP Association Setup Request */
static void pfcp_cp_peer_wait_assoc_setup_resp_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct osmo_pfcp_cp_peer *cp_peer = fi->priv;
	struct osmo_pfcp_msg *m;

	m = osmo_pfcp_cp_peer_new_req(cp_peer, OSMO_PFCP_MSGT_ASSOC_SETUP_REQ);
	m->ies.assoc_setup_req.recovery_time_stamp = cp_peer->ep->recovery_time_stamp;

	m->ies.assoc_setup_req.cp_function_features_present = true;
	osmo_pfcp_bits_set(m->ies.assoc_setup_req.cp_function_features.bits, OSMO_PFCP_CP_FEAT_BUNDL, true);

	m->ctx.resp_cb = on_pfcp_assoc_resp;

	LOG_CP_PEER(cp_peer, LOGL_NOTICE, "Associating with %s...\n",
		    osmo_sockaddr_to_str_c(OTC_SELECT, &cp_peer->remote_addr));

	if (osmo_pfcp_endpoint_tx(cp_peer->ep, m)) {
		LOG_CP_PEER(cp_peer, LOGL_ERROR, "Failed to transmit PFCP Association Setup Request to UPF at %s\n",
			    osmo_sockaddr_to_str_c(OTC_SELECT, &cp_peer->remote_addr));
		osmo_pfcp_cp_peer_fsm_state_chg(PFCP_CP_PEER_ST_WAIT_RETRY);
	}
}

static int on_pfcp_assoc_resp(struct osmo_pfcp_msg *req, struct osmo_pfcp_msg *rx_resp, const char *errmsg)
{
	struct osmo_fsm_inst *fi = req->ctx.peer_fi;
	struct osmo_pfcp_cp_peer *cp_peer = fi->priv;
	enum osmo_pfcp_cause *cause;

	if (!rx_resp) {
		LOG_CP_PEER(cp_peer, LOGL_ERROR, "Error: PFCP Association Setup Response: %s\n",
			    errmsg ? : "no response received");
		goto assoc_failed;
	}

	cause = osmo_pfcp_msg_cause(rx_resp);
	if (!cause) {
		LOG_CP_PEER(cp_peer, LOGL_ERROR, "Invalid PFCP Association Setup Response: no Cause value\n");
		goto assoc_failed;
	}
	if (*cause != OSMO_PFCP_CAUSE_REQUEST_ACCEPTED) {
		LOG_CP_PEER(cp_peer, LOGL_ERROR, "UPF rejected PFCP Association Setup Request with Cause: %s\n",
			    osmo_pfcp_cause_str(*cause));
		goto assoc_failed;
	}

	osmo_fsm_inst_dispatch(fi, PFCP_CP_PEER_EV_RX_ASSOC_SETUP_RESP, rx_resp);
	return 0;

assoc_failed:
	osmo_pfcp_cp_peer_fsm_state_chg(PFCP_CP_PEER_ST_WAIT_RETRY);
	return 0;
}

static void pfcp_cp_peer_wait_assoc_setup_resp_action(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	switch (event) {

	case PFCP_CP_PEER_EV_RX_ASSOC_SETUP_RESP:
		osmo_pfcp_cp_peer_fsm_state_chg(PFCP_CP_PEER_ST_ASSOCIATED);
		break;

	default:
		OSMO_ASSERT(false);
	}
}

static void pfcp_cp_peer_associated_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct osmo_pfcp_cp_peer *cp_peer = fi->priv;
	LOG_CP_PEER(cp_peer, LOGL_NOTICE, "Associated with UPF %s\n",
		    osmo_sockaddr_to_str_c(OTC_SELECT, &cp_peer->remote_addr));
	if (cp_peer->assoc_cb)
		cp_peer->assoc_cb(cp_peer, true);
}

static void pfcp_cp_peer_associated_action(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct osmo_pfcp_cp_peer *cp_peer = fi->priv;

	switch (event) {

	case PFCP_CP_PEER_EV_RX_ASSOC_UPDATE_REQ:
		LOG_CP_PEER(cp_peer, LOGL_ERROR, "PFCP Association Update Request is not implemented\n");
		break;

	default:
		OSMO_ASSERT(false);
	}
}

static void pfcp_cp_peer_associated_onleave(struct osmo_fsm_inst *fi, uint32_t next_state)
{
	struct osmo_pfcp_cp_peer *cp_peer = fi->priv;
	LOG_CP_PEER(cp_peer, LOGL_NOTICE, "Disassociating from UPF %s\n",
		    osmo_sockaddr_to_str_c(OTC_SELECT, &cp_peer->remote_addr));
	if (cp_peer->assoc_cb)
		cp_peer->assoc_cb(cp_peer, false);
}

static void pfcp_cp_peer_graceful_release_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct osmo_pfcp_cp_peer *cp_peer = fi->priv;
	LOG_CP_PEER(cp_peer, LOGL_ERROR, "PFCP graceful release is not implemented\n");
}

static void pfcp_cp_peer_graceful_release_action(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	struct osmo_pfcp_cp_peer *cp_peer = fi->priv;
	LOG_CP_PEER(cp_peer, LOGL_ERROR, "PFCP graceful release is not implemented\n");
}

static void pfcp_cp_peer_wait_use_count_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct osmo_pfcp_cp_peer *cp_peer = fi->priv;
	if (!osmo_use_count_total(&cp_peer->use_count))
		osmo_fsm_inst_term(fi, OSMO_FSM_TERM_REGULAR, NULL);
}

static void pfcp_cp_peer_allstate_action(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	switch (event) {
	case PFCP_CP_PEER_EV_USE_COUNT_ZERO:
		switch (fi->state) {
		default:
			/* still busy, ignore. */
			return;
		case PFCP_CP_PEER_ST_WAIT_USE_COUNT:
			/* Waiting for deallocation; now there are no more users, deallocate. */
			osmo_fsm_inst_term(fi, OSMO_FSM_TERM_REGULAR, NULL);
			return;
		}
	default:
		OSMO_ASSERT(false);
	}
}

#define S(x) (1 << (x))

static const struct osmo_fsm_state pfcp_cp_peer_fsm_states[] = {
	[PFCP_CP_PEER_ST_DISABLED] = {
		.name = "disabled",
		.out_state_mask = 0
			| S(PFCP_CP_PEER_ST_WAIT_ASSOC_SETUP_RESP)
			| S(PFCP_CP_PEER_ST_WAIT_USE_COUNT)
			,
	},
	[PFCP_CP_PEER_ST_WAIT_ASSOC_SETUP_RESP] = {
		.name = "wait_assoc_setup_resp",
		.in_event_mask = 0
			| S(PFCP_CP_PEER_EV_RX_ASSOC_SETUP_RESP)
			,
		.out_state_mask = 0
			| S(PFCP_CP_PEER_ST_ASSOCIATED)
			| S(PFCP_CP_PEER_ST_WAIT_RETRY)
			| S(PFCP_CP_PEER_ST_WAIT_USE_COUNT)
			,
		.onenter = pfcp_cp_peer_wait_assoc_setup_resp_onenter,
		.action = pfcp_cp_peer_wait_assoc_setup_resp_action,
	},
	[PFCP_CP_PEER_ST_WAIT_RETRY] = {
		.name = "wait_retry",
		.out_state_mask = 0
			| S(PFCP_CP_PEER_ST_WAIT_ASSOC_SETUP_RESP)
			| S(PFCP_CP_PEER_ST_WAIT_USE_COUNT)
			,
	},
	[PFCP_CP_PEER_ST_ASSOCIATED] = {
		.name = "associated",
		.in_event_mask = 0
			| S(PFCP_CP_PEER_EV_RX_ASSOC_UPDATE_REQ)
			,
		.out_state_mask = 0
			| S(PFCP_CP_PEER_ST_WAIT_ASSOC_SETUP_RESP)
			| S(PFCP_CP_PEER_ST_GRACEFUL_RELEASE)
			| S(PFCP_CP_PEER_ST_WAIT_USE_COUNT)
			,
		.onenter = pfcp_cp_peer_associated_onenter,
		.action = pfcp_cp_peer_associated_action,
		.onleave = pfcp_cp_peer_associated_onleave,
	},
	[PFCP_CP_PEER_ST_GRACEFUL_RELEASE] = {
		.name = "graceful_release",
		.in_event_mask = 0
			,
		.out_state_mask = 0
			| S(PFCP_CP_PEER_ST_WAIT_RETRY)
			| S(PFCP_CP_PEER_ST_WAIT_USE_COUNT)
			,
		.onenter = pfcp_cp_peer_graceful_release_onenter,
		.action = pfcp_cp_peer_graceful_release_action,
	},
	[PFCP_CP_PEER_ST_WAIT_USE_COUNT] = {
		.name = "wait_use_count",
		.in_event_mask = 0
			| S(PFCP_CP_PEER_EV_USE_COUNT_ZERO)
			,
		.onenter = pfcp_cp_peer_wait_use_count_onenter,
	},
};

static struct osmo_fsm pfcp_cp_peer_fsm = {
	.name = "pfcp_cp_peer",
	.states = pfcp_cp_peer_fsm_states,
	.num_states = ARRAY_SIZE(pfcp_cp_peer_fsm_states),
	.log_subsys = DLPFCP,
	.event_names = pfcp_cp_peer_fsm_event_names,
	.timer_cb = pfcp_cp_peer_fsm_timer_cb,
	.allstate_action = pfcp_cp_peer_allstate_action,
	.allstate_event_mask = 0
		| S(PFCP_CP_PEER_EV_USE_COUNT_ZERO)
		,
};

static __attribute__((constructor)) void pfcp_cp_peer_fsm_register(void)
{
	OSMO_ASSERT(osmo_fsm_register(&pfcp_cp_peer_fsm) == 0);
}

bool osmo_pfcp_cp_peer_is_associated(const struct osmo_pfcp_cp_peer *cp_peer)
{
	return cp_peer && cp_peer->fi->state == PFCP_CP_PEER_ST_ASSOCIATED;
}

void osmo_pfcp_cp_peer_set_msg_ctx(struct osmo_pfcp_cp_peer *cp_peer, struct osmo_pfcp_msg *m)
{
	if (m->ctx.peer_fi)
		return;

	m->ctx.peer_fi = cp_peer->fi;

	m->ctx.peer_use_count = &cp_peer->use_count;
	m->ctx.peer_use_token = (m->rx ? "PFCPrx" : "PFCPtx");
	osmo_use_count_get_put(m->ctx.peer_use_count, m->ctx.peer_use_token, 1);
}

/* Allocate a new PFCP request message to be sent to cp_peer->remote_addr. */
struct osmo_pfcp_msg *osmo_pfcp_cp_peer_new_req(struct osmo_pfcp_cp_peer *cp_peer,
						enum osmo_pfcp_message_type msg_type)
{
	struct osmo_pfcp_msg *m;
	m = osmo_pfcp_msg_alloc_tx_req(cp_peer->ep, &cp_peer->remote_addr, msg_type);
	OSMO_ASSERT(m);
	osmo_pfcp_cp_peer_set_msg_ctx(cp_peer, m);
	return m;
}

/* Allocate a new PFCP response message to be sent to cp_peer->remote_addr. */
struct osmo_pfcp_msg *osmo_pfcp_cp_peer_new_resp(struct osmo_pfcp_cp_peer *cp_peer,
						 const struct osmo_pfcp_msg *in_reply_to,
						 enum osmo_pfcp_message_type msg_type)
{
	struct osmo_pfcp_msg *m;
	m = osmo_pfcp_msg_alloc_tx_resp(cp_peer->ep, in_reply_to, msg_type);
	OSMO_ASSERT(m);
	osmo_pfcp_cp_peer_set_msg_ctx(cp_peer, m);
	return m;
}
