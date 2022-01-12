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

#include <osmocom/core/bits.h>
#include <osmocom/core/msgb.h>
#include <osmocom/gtlv/gtlv.h>

static int next_tl_valid(const struct osmo_gtlv_load *gtlv, const uint8_t **ie_start_p, size_t *buflen_left_p)
{
	const uint8_t *ie_start;
	size_t buflen_left;

	/* Start of next IE, or first IE for first invocation. */
	if (!gtlv->val)
		ie_start = gtlv->src.data;
	else
		ie_start = gtlv->val + gtlv->len;

	/* Sanity */
	if (ie_start < gtlv->src.data || ie_start > gtlv->src.data + gtlv->src.len)
		return -ENOSPC;

	buflen_left = gtlv->src.len - (ie_start - gtlv->src.data);

	/* Too short for parsing an IE? Check also against integer overflow. */
	if (buflen_left && ((buflen_left < gtlv->cfg->tl_min_size) || (buflen_left > gtlv->src.len)))
		return -EBADMSG;

	*ie_start_p = ie_start;
	*buflen_left_p = buflen_left;
	return 0;
}

/* Return a TLV IE from a message buffer.
 *
 * Return the first or next TLV data found in the data buffer, based on the state of the gtlv parameter.
 * When gtlv->val is NULL, return the first IE in the data buffer.
 * Otherwise assume that gtlv points at a valid IE in the data structure, and return the subsequent IE.
 *
 * Usage example:
 *
 *   struct osmo_gtlv gtlv = {
 *           .cfg = osmo_t16l16v_cfg,
 *           .src = { .data = msgb_l3(msg), .len = msgb_l3len(msg) },
 *   };
 *   for (;;) {
 *           if (osmo_gtlv_next(&gtlv)) {
 *                   printf("Error\n");
 *                   break;
 *           }
 *           if (!gtlv.val) {
 *                   printf("End\n");
 *                   break;
 *           }
 *           printf("Tag %u: %zu octets: %s\n", gtlv.tag, gtlv.len, osmo_hexdump(gtlv.val, gtlv.len));
 *   }
 *
 * \param[inout] gtlv  Buffer to return the IE data, and state for TLV parsing position. gtlv->msg should indicate the
 *                   overall message buffer. The other gtlv members should be zero initialized before the first call, and
 *                   remain unchanged between invocations of this function.
 * \returns 0 on success, negative on TLV parsing error. The IE data is returned in gtlv->tag, gtlv->len and gtlv->val;
 *          gtlv->val == NULL if no more IEs remain in the buffer.
 */
int osmo_gtlv_load_next(struct osmo_gtlv_load *gtlv)
{
	const uint8_t *ie_start;
	const uint8_t *ie_end;
	size_t buflen_left;
	int rc;

	rc = next_tl_valid(gtlv, &ie_start, &buflen_left);
	if (rc)
		return rc;

	/* No more IEs? */
	if (!buflen_left) {
		gtlv->val = NULL;
		return 0;
	}

	/* Locate next IE */
	OSMO_ASSERT(gtlv->cfg->load_tl);
	rc = gtlv->cfg->load_tl(gtlv, ie_start, buflen_left);
	if (rc)
		return rc;

	/* Sanity */
	ie_end = gtlv->val + gtlv->len;
	if (ie_end < gtlv->src.data || ie_end > gtlv->src.data + gtlv->src.len)
		return -EBADMSG;

	return 0;
}

/* Return the tag of the IE that osmo_gtlv_next() would yield, do not change the gtlv state.
 *
 * \param[in] gtlv  state for TLV parsing position; is not modified.
 * \returns the tag number on success, negative on TLV parsing error, -ENOENT when no more tags
 *          follow.
 */
int osmo_gtlv_load_peek_tag(const struct osmo_gtlv_load *gtlv)
{
	const uint8_t *ie_start;
	size_t buflen_left;
	int rc;
	/* Guard against modification by load_tl(). */
	struct osmo_gtlv_load mtlv = *gtlv;

	rc = next_tl_valid(&mtlv, &ie_start, &buflen_left);
	if (rc)
		return rc;

	if (!buflen_left)
		return -ENOENT;

	/* Return next IE tag*/
	OSMO_ASSERT(mtlv.cfg->load_tl);
	rc = gtlv->cfg->load_tl(&mtlv, ie_start, buflen_left);
	if (rc)
		return -EBADMSG;
	return mtlv.tag;
}

/* Same as osmo_gtlv_load_next(), but skip any IEs until the given tag is reached. Change the gtlv state only when success
 * is returned.
 * \param[out] gtlv  Return the next IE's TLV info.
 * \param[in] tag  Tag value to match.
 * \return 0 when the tag is found. Return -ENOENT when no such tag follows and keep the gtlv unchanged. */
int osmo_gtlv_load_next_by_tag(struct osmo_gtlv_load *gtlv, unsigned int tag)
{
	struct osmo_gtlv_load work = *gtlv;
	for (;;) {
		int rc = osmo_gtlv_load_next(&work);
		if (rc)
			return rc;
		if (!work.val)
			return -ENOENT;
		if (work.tag == tag) {
			*gtlv = work;
			return 0;
		}
	}
}

/* Put tag header and length at the end of the msgb, according to gtlv->cfg->store_tl().
 * If the length is not known yet, it can be passed as 0 at first, and osmo_gtlv_put_update_tl() can determine the
 * resulting length after the value part was put into the msgb.
 *
 * Usage example:
 *
 *     struct msgb *msg = msgb_alloc(1024, "foo"),
 *     struct osmo_gtlv_put gtlv = {
 *             .cfg = osmo_t16l16v_cfg,
 *             .dst = msg,
 *     }
 *
 *     osmo_gtlv_put_tl(gtlv, 23, 0); // tag 23, length 0 = not known yet
 *
 *     msgb_put(msg, 42);
 *     ...
 *     msgb_put(msg, 42);
 *     ...
 *     msgb_put(msg, 42);
 *
 *     osmo_gtlv_put_update_tl(gtlv);
 *
 * Return 0 on success, -EINVAL if the tag value is invalid, -EMSGSIZE if len is too large.
 */
int osmo_gtlv_put_tl(struct osmo_gtlv_put *gtlv, unsigned int tag, size_t len)
{
	int rc;
	uint8_t *last_tl;
	OSMO_ASSERT(gtlv->cfg->store_tl);
	last_tl = gtlv->dst->tail;
	rc = gtlv->cfg->store_tl(gtlv->dst->tail, msgb_tailroom(gtlv->dst), tag, len, gtlv);
	if (rc < 0)
		return rc;
	if (rc > 0)
		msgb_put(gtlv->dst, rc);
	gtlv->last_tag = tag;
	gtlv->last_tl = last_tl;
	gtlv->last_val = gtlv->dst->tail;
	return 0;
}

/* Update the length of the last put IE header (last call to osmo_gtlv_put_tl()) to match with the current
 * gtlv->dst->tail.
 * Return 0 on success, -EMSGSIZE if the amount of data written since osmo_gtlv_put_tl() is too large.
 */
int osmo_gtlv_put_update_tl(struct osmo_gtlv_put *gtlv)
{
	size_t len = gtlv->dst->tail - gtlv->last_val;
	int rc = gtlv->cfg->store_tl(gtlv->last_tl, gtlv->last_val - gtlv->last_tl, gtlv->last_tag, len, gtlv);
	if (rc < 0)
		return rc;
	/* In case the TL has changed in size, hopefully the implementation has moved the msgb data. Make sure last_val
	 * points at the right place now. */
	gtlv->last_val = gtlv->last_tl + rc;
	return 0;
}

static int t8l8v_load_tl(struct osmo_gtlv_load *gtlv, const uint8_t *src_data, size_t src_data_len)
{
	/* already validated in next_tl_valid(): src_data_len >= cfg->tl_min_size == 2. */
	gtlv->tag = src_data[0];
	gtlv->len = src_data[1];
	gtlv->val = src_data + 2;
	return 0;
}

static int t8l8v_store_tl(uint8_t *dst_data, size_t dst_data_avail, unsigned int tag, size_t len,
			  struct osmo_gtlv_put *gtlv)
{
	if (tag > UINT8_MAX)
		return -EINVAL;
	if (len > UINT8_MAX)
		return -EMSGSIZE;
	if (dst_data_avail < 2)
		return -ENOSPC;
	dst_data[0] = tag;
	dst_data[1] = len;
	return 2;
}

const struct osmo_gtlv_cfg osmo_t8l8v_cfg = {
	.tl_min_size = 2,
	.load_tl = t8l8v_load_tl,
	.store_tl = t8l8v_store_tl,
};

static int t16l16v_load_tl(struct osmo_gtlv_load *gtlv, const uint8_t *src_data, size_t src_data_len)
{
	/* already validated in next_tl_valid(): src_data_len >= cfg->tl_min_size == 4. */
	gtlv->tag = osmo_load16be(src_data);
	gtlv->len = osmo_load16be(src_data + 2);
	gtlv->val = src_data + 4;
	return 0;
}

static int t16l16v_store_tl(uint8_t *dst_data, size_t dst_data_avail, unsigned int tag, size_t len,
			    struct osmo_gtlv_put *gtlv)
{
	if (tag > UINT16_MAX)
		return -EINVAL;
	if (len > UINT16_MAX)
		return -EMSGSIZE;
	if (dst_data_avail < 4)
		return -ENOSPC;
	osmo_store16be(tag, dst_data);
	osmo_store16be(len, dst_data + 2);
	return 4;
}

const struct osmo_gtlv_cfg osmo_t16l16v_cfg = {
	.tl_min_size = 4,
	.load_tl = t16l16v_load_tl,
	.store_tl = t16l16v_store_tl,
};
