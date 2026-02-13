/*
 * (C) 2021-2025 by sysmocom - s.f.m.c. GmbH <info@sysmocom.de>
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

#include <osmocom/core/hashtable.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/osmo_io.h>
#include <osmocom/pfcp/pfcp_endpoint.h>


/* Send/receive PFCP messages to/from remote PFCP endpoints. */
struct osmo_pfcp_endpoint {
	struct osmo_pfcp_endpoint_cfg cfg;

	/* PFCP socket */
	struct osmo_io_fd *iofd;

	/* The time at which this endpoint last restarted, as seconds since unix epoch. */
	uint32_t recovery_time_stamp;

	/* State for determining the next sequence number for transmitting a request message */
	uint32_t seq_nr_state;

	/* List of struct osmo_pfcp_cp_peer */
	struct llist_head cp_peer_list;

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
