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
#include <string.h>

#include <osmocom/core/endian.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/fsm.h>
#include <osmocom/core/use_count.h>
#include <osmocom/core/bitvec.h>

#include <osmocom/pfcp/pfcp_msg.h>
#include <osmocom/gtlv/gtlv_dec_enc.h>

/* Assumes presence of local variable osmo_pfcp_msg *m. m->log_ctx may be NULL. */
#define RETURN_ERROR(RC, FMT, ARGS...) \
	do {\
		OSMO_ASSERT(m); \
		OSMO_LOG_PFCP_MSG(m, LOGL_ERROR, FMT " (%d: %s)\n", ##ARGS, RC, strerror((RC) > 0 ? (RC) : -(RC))); \
		return RC; \
	} while (0)

bool osmo_pfcp_msgtype_is_response(enum osmo_pfcp_message_type message_type)
{
	switch (message_type) {
	case OSMO_PFCP_MSGT_HEARTBEAT_RESP:
	case OSMO_PFCP_MSGT_PFD_MGMT_RESP:
	case OSMO_PFCP_MSGT_ASSOC_SETUP_RESP:
	case OSMO_PFCP_MSGT_ASSOC_UPDATE_RESP:
	case OSMO_PFCP_MSGT_ASSOC_RELEASE_RESP:
	case OSMO_PFCP_MSGT_VERSION_NOT_SUPP_RESP:
	case OSMO_PFCP_MSGT_NODE_REPORT_RESP:
	case OSMO_PFCP_MSGT_SESSION_SET_DEL_RESP:
	case OSMO_PFCP_MSGT_SESSION_EST_RESP:
	case OSMO_PFCP_MSGT_SESSION_MOD_RESP:
	case OSMO_PFCP_MSGT_SESSION_DEL_RESP:
	case OSMO_PFCP_MSGT_SESSION_REP_RESP:
		return true;
	default:
		return false;
	}
}

struct osmo_pfcp_header_common {
#if OSMO_IS_LITTLE_ENDIAN
	uint8_t seid_present:1,
		message_priority_present:1,
		follow_on:1,
		spare:2,
		version:3;
	uint8_t message_type;
	uint16_t message_length;
#elif OSMO_IS_BIG_ENDIAN
/* auto-generated from the little endian part above (libosmocore/contrib/struct_endianess.py) */
	uint8_t version:3, spare:2, follow_on:1, message_priority_present:1, seid_present:1;
	uint8_t message_type;
	uint16_t message_length;
#endif
} __attribute__ ((packed));

struct osmo_pfcp_header_no_seid {
	struct osmo_pfcp_header_common c;
	uint8_t sequence_nr[3];
	uint8_t spare;
} __attribute__ ((packed));

struct osmo_pfcp_header_seid {
#if OSMO_IS_LITTLE_ENDIAN
	struct osmo_pfcp_header_common c;
	uint64_t session_endpoint_identifier;
	uint8_t sequence_nr[3];
	uint8_t message_priority:4,
		spare:4;
#elif OSMO_IS_BIG_ENDIAN
/* auto-generated from the little endian part above (libosmocore/contrib/struct_endianess.py) */
	struct osmo_pfcp_header_common c;
	uint64_t session_endpoint_identifier;
	uint8_t sequence_nr[3];
	uint8_t spare:4, message_priority:4;
#endif
} __attribute__ ((packed));

int osmo_pfcp_ie_node_id_from_osmo_sockaddr(struct osmo_pfcp_ie_node_id *node_id, const struct osmo_sockaddr *os)
{
	switch (os->u.sa.sa_family) {
	case AF_INET:
		node_id->type = OSMO_PFCP_NODE_ID_T_IPV4;
		break;
	case AF_INET6:
		node_id->type = OSMO_PFCP_NODE_ID_T_IPV6;
		break;
	default:
		return -ENOTSUP;
	}
	node_id->ip = *os;
	return 0;
}

int osmo_pfcp_ie_node_id_to_osmo_sockaddr(const struct osmo_pfcp_ie_node_id *node_id, struct osmo_sockaddr *os)
{
	switch (node_id->type) {
	case OSMO_PFCP_NODE_ID_T_IPV4:
		if (os->u.sa.sa_family != AF_INET)
			return -EINVAL;
		break;
	case OSMO_PFCP_NODE_ID_T_IPV6:
		if (os->u.sa.sa_family != AF_INET6)
			return -EINVAL;
		break;
	default:
		return -ENOTSUP;
	}
	*os = node_id->ip;
	return 0;
}

static int pfcp_header_set_message_length(struct osmo_pfcp_header_common *c, unsigned int header_and_payload_len)
{
	if (header_and_payload_len < sizeof(struct osmo_pfcp_header_common))
		return -EINVAL;
	if (header_and_payload_len - sizeof(struct osmo_pfcp_header_common) > UINT16_MAX)
		return -EMSGSIZE;
	osmo_store16be(header_and_payload_len - sizeof(struct osmo_pfcp_header_common),
		       &c->message_length);
	return 0;
}

static unsigned int pfcp_header_get_message_length(const struct osmo_pfcp_header_common *c)
{
	unsigned int len = osmo_load16be(&c->message_length);
	return len + sizeof(struct osmo_pfcp_header_common);
}

/*! Encode and append the given PFCP header to a msgb.
 * \param[out] msg message buffer to which to push the header.
 * \param[in] to-be-encoded representation of PFCP header. */
static int enc_pfcp_header(struct msgb *msg, const struct osmo_pfcp_msg *m)
{
	const struct osmo_pfcp_header_parsed *parsed = &m->h;
	struct osmo_pfcp_header_seid *h_seid = NULL;
	struct osmo_pfcp_header_no_seid *h_no_seid = NULL;
	struct osmo_pfcp_header_common *c;
	int rc;

	if (!parsed->seid_present) {
		h_no_seid = (struct osmo_pfcp_header_no_seid *)msgb_put(msg, sizeof(struct osmo_pfcp_header_no_seid));
		c = &h_no_seid->c;
	} else {
		h_seid = (struct osmo_pfcp_header_seid *)msgb_put(msg, sizeof(struct osmo_pfcp_header_seid));
		c = &h_seid->c;
	}

	*c = (struct osmo_pfcp_header_common){
		.version = parsed->version,
		.message_priority_present = (parsed->priority_present ? 1 : 0),
		.seid_present = (parsed->seid_present ? 1 : 0),
		.message_type = parsed->message_type,
	};

	/* Put a preliminary length reflecting only the header, until it is updated later in osmo_pfcp_msg_encode(). */
	rc = pfcp_header_set_message_length(c, parsed->seid_present ? sizeof(struct osmo_pfcp_header_seid)
								    : sizeof(struct osmo_pfcp_header_no_seid));
	if (rc)
		RETURN_ERROR(rc, "Problem with PFCP message length");

	if (!parsed->seid_present) {
		osmo_store32be_ext(parsed->sequence_nr, h_no_seid->sequence_nr, 3);
		if (parsed->priority_present)
			RETURN_ERROR(-EINVAL, "Message Priority can only be present when the SEID is also present");
	} else {
		osmo_store64be(parsed->seid, &h_seid->session_endpoint_identifier);
		osmo_store32be_ext(parsed->sequence_nr, h_seid->sequence_nr, 3);
		if (parsed->priority_present)
			h_seid->message_priority = parsed->priority;
	}

	return 0;
}

static void osmo_pfcp_msg_set_memb_ofs(struct osmo_pfcp_msg *m)
{
	const struct osmo_gtlv_coding *mc = osmo_pfcp_get_msg_coding(m->h.message_type);
	m->ofs_cause = 0;
	m->ofs_node_id = 0;
	if (!mc)
		return;
	for (; !osmo_gtlv_coding_end(mc) && (m->ofs_cause == 0 || m->ofs_node_id == 0); mc++) {
		if (mc->ti.tag == OSMO_PFCP_IEI_CAUSE)
			m->ofs_cause = offsetof(struct osmo_pfcp_msg, ies) + mc->memb_ofs;
		if (mc->ti.tag == OSMO_PFCP_IEI_NODE_ID)
			m->ofs_node_id = offsetof(struct osmo_pfcp_msg, ies) + mc->memb_ofs;
	}
};

/*! Decode a single PFCP message's header.
 *
 * If msg->l4h is non-NULL, decode at msgb_l4(msg). If l4h is NULL, decode at msgb_l3(msg).
 * In case of bundled PFCP messages, decode only one message and return the offset to the next message in the buffer.
 * Hence, to decode a message bundle, increment msg->l4h until all messages are decoded:
 *
 *   msg->l4h = msg->l3h;
 *   while (msgb_l4len(msg)) {
 *           struct osmo_pfcp_msg m;
 *           struct osmo_gtlv_load tlv;
 *           int rc;
 *           rc = osmo_pfcp_msg_decode_header(&tlv, &m, msg);
 *           if (rc < 0)
 *                  error();
 *           msg->l4h += rc;
 *
 *           if (osmo_pfcp_msg_decode_tlv(&m, &tlv))
 *                  error();
 *           handle(&m);
 *   }
 *
 * \param[out] tlv  Return TLV start pointer and length in tlv->src.*.
 * \param[inout] m  Place the decoded data in m->h; use m->ctx.* as logging context.
 * \param[in] msg  PFCP data to parse, possibly containing a PFCP message bundle.
 * \return total single PFCP message length (<= data_len) on success, negative on error.
 */
int osmo_pfcp_msg_decode_header(struct osmo_gtlv_load *tlv, struct osmo_pfcp_msg *m,
				const struct msgb *msg)
{
	struct osmo_pfcp_header_parsed *parsed = &m->h;
	const uint8_t *pfcp_msg_data;
	unsigned int pfcp_msg_data_len;
	unsigned int header_len;
	unsigned int message_length;
	const struct osmo_pfcp_header_common *c;

	if (msg->l4h) {
		pfcp_msg_data = msgb_l4(msg);
		pfcp_msg_data_len = msgb_l4len(msg);
	} else {
		pfcp_msg_data = msgb_l3(msg);
		pfcp_msg_data_len = msgb_l3len(msg);
	}

	if (!pfcp_msg_data || !pfcp_msg_data_len)
		RETURN_ERROR(-EINVAL, "No Layer 3 data in this message buffer");

	if (pfcp_msg_data_len < sizeof(struct osmo_pfcp_header_common))
		RETURN_ERROR(-EINVAL, "Message too short for PFCP header: %u", pfcp_msg_data_len);

	c = (void *)pfcp_msg_data;

	header_len = (c->seid_present ? sizeof(struct osmo_pfcp_header_seid) : sizeof(struct osmo_pfcp_header_no_seid));
	if (pfcp_msg_data_len < header_len)
		RETURN_ERROR(-EINVAL, "Message too short for PFCP header: %u", pfcp_msg_data_len);

	*parsed = (struct osmo_pfcp_header_parsed){
		.version = c->version,
		.priority_present = (bool)c->message_priority_present,
		.seid_present = (bool)c->seid_present,
		.message_type = c->message_type,
	};

	m->is_response = osmo_pfcp_msgtype_is_response(parsed->message_type);
	osmo_pfcp_msg_set_memb_ofs(m);

	message_length = pfcp_header_get_message_length(c);
	if (message_length > pfcp_msg_data_len)
		RETURN_ERROR(-EMSGSIZE,
			     "The header's indicated total message length %u is larger than the received data %u",
			     message_length, pfcp_msg_data_len);

	/* T16L16V payload data and len */
	*tlv = (struct osmo_gtlv_load){
		.cfg = &osmo_t16l16v_cfg,
		.src = {
			.data = pfcp_msg_data + header_len,
			.len = message_length - header_len,
		},
	};

	if (c->follow_on) {
		/* Another PFCP message should follow */
		if (pfcp_msg_data_len - message_length < sizeof(struct osmo_pfcp_header_common))
			OSMO_LOG_PFCP_MSG(m, LOGL_INFO,
					  "PFCP message indicates more messages should follow in the bundle,"
					  " but remaining size %u is too short", pfcp_msg_data_len - message_length);
	} else {
		/* No more PFCP message should follow in the bundle */
		if (pfcp_msg_data_len > message_length)
			OSMO_LOG_PFCP_MSG(m, LOGL_INFO, "Surplus data after PFCP message: %u",
					  pfcp_msg_data_len - message_length);
	}

	if (!parsed->seid_present) {
		const struct osmo_pfcp_header_no_seid *h_no_seid = (void *)pfcp_msg_data;
		parsed->sequence_nr = osmo_load32be_ext_2(h_no_seid->sequence_nr, 3);
		if (parsed->priority_present)
			RETURN_ERROR(-EINVAL, "Message Priority can only be present when the SEID is also present");
	} else {
		const struct osmo_pfcp_header_seid *h_seid = (void *)pfcp_msg_data;
		parsed->seid = osmo_load64be(&h_seid->session_endpoint_identifier);
		parsed->sequence_nr = osmo_load32be_ext_2(h_seid->sequence_nr, 3);
		if (parsed->priority_present)
			parsed->priority = h_seid->message_priority;
	}

	return message_length;
}

void osmo_pfcp_msg_err_cb(void *data, void *decoded_struct, const char *file, int line, const char *fmt, ...)
{
	va_list ap;
	if (log_check_level(DLPFCP, LOGL_ERROR)) {
		char *errmsg;

		va_start(ap, fmt);
		errmsg = talloc_vasprintf(OTC_SELECT, fmt, ap);
		va_end(ap);
		OSMO_LOG_PFCP_MSG_SRC((struct osmo_pfcp_msg *)data, LOGL_ERROR, file, line, "%s", errmsg);
	}
}

int osmo_pfcp_msg_decode_tlv(struct osmo_pfcp_msg *m, struct osmo_gtlv_load *tlv)
{
	return osmo_pfcp_ies_decode(&m->ies, tlv, false, m->h.message_type, osmo_pfcp_msg_err_cb, m, osmo_pfcp_iei_strs);
}

static int osmo_pfcp_msg_encode_tlv(struct msgb *msg, const struct osmo_pfcp_msg *m)
{
	struct osmo_gtlv_put tlv = {
		.cfg = &osmo_t16l16v_cfg,
		.dst = msg,
	};
	return osmo_pfcp_ies_encode(&tlv, &m->ies, m->h.message_type, osmo_pfcp_msg_err_cb, (void *)m, osmo_pfcp_iei_strs);
}

/* Append the encoded PFCP message to the message buffer.
 *
 * If msg->l3h is NULL, point it at the start of the encoded message.
 * Always point msg->l4h at the start of the newly encoded message.
 * Hence, in a message bundle, msg->l3h always points at the first PFCP message, while msg->l4h always points at the
 * last PFCP message.
 *
 * When adding a PFCP message to a bundle, set the Follow On (FO) flag of the previously last message to 1, and of the
 * newly encoded, now last message as 0.
 *
 * To log errors to a specific osmo_fsm_inst, point m->log_ctx to that instance before calling this function. Otherwise
 * set log_ctx = NULL.
 *
 * \return 0 on success, negative on error. */
int osmo_pfcp_msg_encode(struct msgb *msg, const struct osmo_pfcp_msg *m)
{
	struct osmo_pfcp_header_common *c;
	int rc;

	/* Forming a bundle? If yes, set the Follow On flag of the currently last message to 1 */
	if (msg->l4h && msgb_l4len(msg)) {
		c = msgb_l4(msg);
		c->follow_on = 1;
	}
	/* Make sure l3h points at the first PFCP message in a message bundle */
	if (!msg->l3h)
		msg->l3h = msg->tail;
	/* Make sure l4h points at the last PFCP message in a message bundle */
	msg->l4h = msg->tail;
	c = (void *)msg->tail;

	rc = enc_pfcp_header(msg, m);
	if (rc)
		return rc;

	rc = osmo_pfcp_msg_encode_tlv(msg, m);
	if (rc)
		return rc;

	/* Update the header's message_length */
	rc = pfcp_header_set_message_length(c, msgb_l4len(msg));
	if (rc)
		RETURN_ERROR(rc, "Problem with PFCP message length");
	return 0;
}

static int osmo_pfcp_msg_destructor(struct osmo_pfcp_msg *m);

static struct osmo_pfcp_msg *_osmo_pfcp_msg_alloc(void *ctx, const struct osmo_sockaddr *remote_addr)
{
	struct osmo_pfcp_msg *m = talloc(ctx, struct osmo_pfcp_msg);
	*m = (struct osmo_pfcp_msg){
		.remote_addr = *remote_addr,
		.h = {
			.version = 1,
		},
	};
	talloc_set_destructor(m, osmo_pfcp_msg_destructor);
	return m;
}

struct osmo_pfcp_msg *osmo_pfcp_msg_alloc_rx(void *ctx, const struct osmo_sockaddr *remote_addr)
{
	struct osmo_pfcp_msg *rx = _osmo_pfcp_msg_alloc(ctx, remote_addr);
	rx->rx = true;
	return rx;
}

static struct osmo_pfcp_msg *osmo_pfcp_msg_alloc_tx(void *ctx, const struct osmo_sockaddr *remote_addr,
						    const struct osmo_pfcp_msg *in_reply_to,
						    enum osmo_pfcp_message_type msg_type)
{
	struct osmo_pfcp_msg *tx;
	if (!remote_addr && in_reply_to)
		remote_addr = &in_reply_to->remote_addr;
	OSMO_ASSERT(remote_addr);
	tx = _osmo_pfcp_msg_alloc(ctx, remote_addr);
	OSMO_ASSERT(tx);
	tx->is_response = osmo_pfcp_msgtype_is_response(msg_type);
	tx->h.message_type = msg_type;
	if (in_reply_to)
		tx->h.sequence_nr = in_reply_to->h.sequence_nr;
	osmo_pfcp_msg_set_memb_ofs(tx);
	return tx;
}

/* Allocate a new PFCP Request message to be transmitted to a peer. */
struct osmo_pfcp_msg *osmo_pfcp_msg_alloc_tx_req(void *ctx, const struct osmo_sockaddr *remote_addr,
						 enum osmo_pfcp_message_type msg_type)
{
	return osmo_pfcp_msg_alloc_tx(ctx, remote_addr, NULL, msg_type);
}

/* Allocate a new PFCP Response message to be transmitted to a peer, as a response to a received PFCP message.
 * Pass the received PFCP Request in in_reply_to; take the remote address and sequence nr from in_reply_to. */
struct osmo_pfcp_msg *osmo_pfcp_msg_alloc_tx_resp(void *ctx, const struct osmo_pfcp_msg *in_reply_to,
						  enum osmo_pfcp_message_type msg_type)
{
	return osmo_pfcp_msg_alloc_tx(ctx, NULL, in_reply_to, msg_type);
}

static int osmo_pfcp_msg_destructor(struct osmo_pfcp_msg *m)
{
	OSMO_LOG_PFCP_MSG(m, LOGL_DEBUG, "discarding\n");
	if (m->ctx.session_use_count)
		OSMO_ASSERT(osmo_use_count_get_put(m->ctx.session_use_count, m->ctx.session_use_token, -1) == 0);
	m->ctx.session_fi = NULL;
	m->ctx.session_use_count = NULL;
	m->ctx.session_use_token = NULL;

	if (m->ctx.peer_use_count)
		OSMO_ASSERT(osmo_use_count_get_put(m->ctx.peer_use_count, m->ctx.peer_use_token, -1) == 0);
	m->ctx.peer_fi = NULL;
	m->ctx.peer_use_count = NULL;
	m->ctx.peer_use_token = NULL;
	return 0;
}

void osmo_pfcp_msg_free(struct osmo_pfcp_msg *m)
{
	if (!m)
		return;
	talloc_free(m);
}

uint32_t osmo_pfcp_next_seq_nr(uint32_t *next_seq_nr_state)
{
	(*next_seq_nr_state)++;
	(*next_seq_nr_state) &= 0xffffff;
	/* Avoid seq == 0, so that it doesn't look like the value is missing. */
	if (!(*next_seq_nr_state))
		(*next_seq_nr_state)++;
	return *next_seq_nr_state;
}

uint64_t osmo_pfcp_next_seid(uint64_t *next_seid_state)
{
	(*next_seid_state)++;
	/* Avoid SEID == 0, which is sent in Session Establishment Request before a remote SEID is known. */
	if (!*next_seid_state)
		(*next_seid_state)++;
	return *next_seid_state;
}

/* Set either dst->v4 or dst->v6 to addr, depending on addr->family. Set the IP address to addr and port to 0, not
 * copying the port information from addr. Return zero on success, negative on error (i.e. no known family in addr). */
int osmo_pfcp_ip_addrs_set(struct osmo_pfcp_ip_addrs *dst, const struct osmo_sockaddr *addr)
{
	switch (addr->u.sas.ss_family) {
	case AF_INET:
		dst->v4_present = true;
		dst->v4 = *addr;
		osmo_sockaddr_set_port(&dst->v4.u.sa, 0);
		return 0;
	case AF_INET6:
		dst->v6_present = true;
		dst->v6 = *addr;
		osmo_sockaddr_set_port(&dst->v6.u.sa, 0);
		return 0;
	default:
		return -ENOTSUP;
	}
}

/* If a osmo_fsm_inst placed in m->ctx deallocates before the osmo_pfcp_msg, call this function, to make sure to avoid
 * use after free. Alternatively use m->ctx.*_use_count to make sure the FSM inst does not deallocate before the
 * osmo_pfcp_msg is discarded from the resend queue. */
void osmo_pfcp_msg_invalidate_ctx(struct osmo_pfcp_msg *m, struct osmo_fsm_inst *deleted_fi)
{
	if (m->ctx.session_fi == deleted_fi) {
		m->ctx.session_fi = NULL;
		m->ctx.session_use_count = NULL;
		m->ctx.session_use_token = NULL;
	}
	if (m->ctx.peer_fi == deleted_fi) {
		m->ctx.peer_fi = NULL;
		m->ctx.peer_use_count = NULL;
		m->ctx.peer_use_token = NULL;
	}
}

int osmo_pfcp_msg_to_str_buf(char *buf, size_t buflen, const struct osmo_pfcp_msg *m)
{
	struct osmo_strbuf sb = { .buf = buf, .len = buflen };
	OSMO_STRBUF_PRINTF(sb, "PFCPv%u %s hdr={seq=%u", m->h.version, osmo_pfcp_message_type_str(m->h.message_type),
			   m->h.sequence_nr);
	if (m->h.priority_present)
		OSMO_STRBUF_PRINTF(sb, " prio=%u", m->h.priority);
	if (m->h.seid_present)
		OSMO_STRBUF_PRINTF(sb, " SEID=0x%"PRIx64, m->h.seid);
	OSMO_STRBUF_PRINTF(sb, "} ies={");
	OSMO_STRBUF_APPEND(sb, osmo_pfcp_ies_encode_to_str, &m->ies, m->h.message_type, osmo_pfcp_iei_strs);
	OSMO_STRBUF_PRINTF(sb, " }");
	return sb.chars_needed;
}

char *osmo_pfcp_msg_to_str_c(void *ctx, const struct osmo_pfcp_msg *m)
{
	OSMO_NAME_C_IMPL(ctx, 256, "ERROR", osmo_pfcp_msg_to_str_buf, m)
}
