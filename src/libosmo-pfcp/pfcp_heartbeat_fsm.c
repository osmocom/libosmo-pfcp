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

#include <osmocom/core/utils.h>
#include <osmocom/core/fsm.h>
#include <osmocom/core/tdef.h>

#include <osmocom/pfcp/pfcp_heartbeat_fsm.h>

enum heartbeat_fsm_state {
	HEARTBEAT_ST_IDLE,
	HEARTBEAT_ST_WAIT_RESP,
};

static const struct value_string heartbeat_fsm_event_names[] = {
	OSMO_VALUE_STRING(OSMO_PFCP_HEARTBEAT_EV_RX_RESP),
	OSMO_VALUE_STRING(OSMO_PFCP_HEARTBEAT_EV_RX_REQ),
	{}
};

static struct osmo_fsm heartbeat_fsm;

static const struct osmo_tdef_state_timeout heartbeat_fsm_timeouts[32] = {
	[HEARTBEAT_ST_IDLE] = { .T = -19 },
	[HEARTBEAT_ST_WAIT_RESP] = { .T = -20 },
};

/* Transition to a state, using the T timer defined in heartbeat_fsm_timeouts.
 * Assumes local variable fi exists. */
#define heartbeat_state_chg(state) \
	osmo_tdef_fsm_inst_state_chg(fi, state, \
				     heartbeat_fsm_timeouts, \
				     ((struct heartbeat*)(fi->priv))->tdefs, \
				     5)

struct heartbeat {
	struct osmo_fsm_inst *fi;
	uint32_t parent_event_tx_heartbeat;
	struct osmo_tdef *tdefs;
};

struct osmo_fsm_inst *osmo_pfcp_heartbeat_alloc(struct osmo_fsm_inst *parent_fi,
						uint32_t parent_event_tx_heartbeat, uint32_t parent_event_term,
						struct osmo_tdef *tdefs)
{
	struct heartbeat *heartbeat;

	struct osmo_fsm_inst *fi = osmo_fsm_inst_alloc_child(&heartbeat_fsm, parent_fi, parent_event_term);
	OSMO_ASSERT(fi);

	heartbeat = talloc(fi, struct heartbeat);
	OSMO_ASSERT(heartbeat);
	fi->priv = heartbeat;
	*heartbeat = (struct heartbeat){
		.fi = fi,
		.parent_event_tx_heartbeat = parent_event_tx_heartbeat,
		.tdefs = tdefs,
	};

	return heartbeat->fi;
}

static int heartbeat_fsm_timer_cb(struct osmo_fsm_inst *fi)
{
	/* Return 1 to terminate FSM instance, 0 to keep running */
	switch (fi->state) {
	case HEARTBEAT_ST_IDLE:
		/* Time for another heartbeat request */
		heartbeat_state_chg(HEARTBEAT_ST_WAIT_RESP);
		return 0;
	case HEARTBEAT_ST_WAIT_RESP:
		/* Response did not arrive. Emit parent_event_term to the parent_fi. */
		return 1;
	default:
		OSMO_ASSERT(false);
	}
}

static void pfcp_heartbeat_idle_action(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	switch (event) {

	case OSMO_PFCP_HEARTBEAT_EV_RX_RESP:
		/* A retransmission? */
	case OSMO_PFCP_HEARTBEAT_EV_RX_REQ:
		/* Either way, if we've seen any Heartbeat message from the peer, consider a Heartbeat to have succeeded
		 * and restart the idle timeout. */
		heartbeat_state_chg(HEARTBEAT_ST_IDLE);
		return;

	default:
		OSMO_ASSERT(false);
	}
}

static void pfcp_heartbeat_wait_resp_onenter(struct osmo_fsm_inst *fi, uint32_t prev_state)
{
	struct heartbeat *heartbeat = fi->priv;
	/* Let the caller's implementation figure out how exactly to encode the Heartbeat Request and send it.
	 * Just dispatching events here. */
	osmo_fsm_inst_dispatch(fi->proc.parent, heartbeat->parent_event_tx_heartbeat, NULL);
}

static void pfcp_heartbeat_wait_resp_action(struct osmo_fsm_inst *fi, uint32_t event, void *data)
{
	switch (event) {

	case OSMO_PFCP_HEARTBEAT_EV_RX_RESP:
		heartbeat_state_chg(HEARTBEAT_ST_IDLE);
		break;

	case OSMO_PFCP_HEARTBEAT_EV_RX_REQ:
		/* Doesn't matter whether the peer is also requesting, still waiting for the response to our own
		 * request. */
		break;

	default:
		OSMO_ASSERT(false);
	}
}

#define S(x)    (1 << (x))

static const struct osmo_fsm_state heartbeat_fsm_states[] = {
	[HEARTBEAT_ST_IDLE] = {
		.name = "idle",
		.in_event_mask = 0
			,
		.out_state_mask = 0
			| S(HEARTBEAT_ST_WAIT_RESP)
			| S(HEARTBEAT_ST_IDLE)
			,
		.action = pfcp_heartbeat_idle_action,
	},
	[HEARTBEAT_ST_WAIT_RESP] = {
		.name = "wait_resp",
		.in_event_mask = 0
			| S(OSMO_PFCP_HEARTBEAT_EV_RX_RESP)
			| S(OSMO_PFCP_HEARTBEAT_EV_RX_REQ)
			,
		.out_state_mask = 0
			| S(HEARTBEAT_ST_IDLE)
			,
		.onenter = pfcp_heartbeat_wait_resp_onenter,
		.action = pfcp_heartbeat_wait_resp_action,
	},
};

static struct osmo_fsm pfcp_heartbeat_fsm = {
	.name = "pfcp_heartbeat",
	.states = heartbeat_fsm_states,
	.num_states = ARRAY_SIZE(heartbeat_fsm_states),
	.log_subsys = DLPFCP,
	.event_names = heartbeat_fsm_event_names,
	.timer_cb = heartbeat_fsm_timer_cb,
};

static __attribute__((constructor)) void pfcp_heartbeat_fsm_register(void)
{
	OSMO_ASSERT(osmo_fsm_register(&pfcp_heartbeat_fsm) == 0);
}
