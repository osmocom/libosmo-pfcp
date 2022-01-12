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

struct osmo_fsm_inst;
struct osmo_tdef;

enum osmo_pfcp_heartbeat_fsm_event {
	/* Dispatch this with a struct osmo_pfcp_msg* as data argument whenever a Heartbeat Response matching this
	 * instance is received. Typically a PFCP Peer responds to a request sent from here. */
	OSMO_PFCP_HEARTBEAT_EV_RX_RESP,
	/* Dispatch this with a struct osmo_pfcp_msg* as data argument whenever a Heartbeat Request matching this
	 * instance is received. Typically a PFCP Peer on its own accord sent a Heartbeat Request. */
	OSMO_PFCP_HEARTBEAT_EV_RX_REQ,
};

struct osmo_fsm_inst *osmo_pfcp_heartbeat_alloc(struct osmo_fsm_inst *parent_fi,
						uint32_t parent_event_tx_heartbeat, uint32_t parent_event_term,
						struct osmo_tdef *tdefs);
