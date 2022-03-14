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
#include <stdio.h>
#include <stdbool.h>

struct msgb;
struct osmo_gtlv_load;
struct osmo_gtlv_put;
struct value_string;

struct osmo_gtlv_tag_inst {
	unsigned int tag;
	bool instance_present;
	unsigned int instance;
};

int osmo_gtlv_tag_inst_cmp(const struct osmo_gtlv_tag_inst *a, const struct osmo_gtlv_tag_inst *b);

int osmo_gtlv_tag_inst_to_str_buf(char *buf, size_t buflen, const struct osmo_gtlv_tag_inst *ti,
				 const struct value_string *tag_names);
char *osmo_gtlv_tag_inst_to_str_c(void *ctx, const struct osmo_gtlv_tag_inst *ti,
				 const struct value_string *tag_names);

/*! TL configuration for osmo_gtlv_load*() and osmo_gtlv_put*(). Depending on these implementations provided by the caller,
 * osmo_gtlv can load any sizes of tag and length fields (that don't surpass the value range of unsigned int and size_t,
 * respectively), as well as TV (fixed-length) or TvLV (variable-sized length).
 *
 * See osmo_t8l8v_cfg and osmo_t16l16v_cfg, ready implementations for plain 8bit and 16bit TLV protocols.
 *
 * libosmo-pfcp serves as example for using this entire TLV API, uncluding de/encoding to structs and generating parts
 * of the TLV parsing code based on message definitions. It uses osmo_t16l16v_cfg.
 */
struct osmo_gtlv_cfg {
	/*! The length in bytes of the shortest possible TL header (e.g. 4 for T16L16V, or 1 for 8bit tags where TV IEs
	 * without a length exist). A src_data_len passed to store_tl() below is guaranteed to be >= this value. If at
	 * any point there is remaining message data smaller than this value, a parsing error is returned.
	 */
	size_t tl_min_size;

	/*! Read one TL from the start of src_data.
	 * \param gtlv  Return the T (tag) value read from src_data in gtlv->tag.
	 *             Return the L (length) value read from src_data in gtlv->len.
	 *             Return the I (instance) value read from src_data in gtlv->len; ignore if there is no I.
	 *             Return the position just after the TL in gtlv->*val. If there is V data, point at the start of the
	 *             V data in src_data. If there is no V data, point at the byte just after the TL part in src_data.
	 * \param src_data  Part of raw message being decoded.
	 * \param src_data_len  Remaining message data length at src_data.
	 * \return 0 on success, negative on error.
	 */
	int (*load_tl)(struct osmo_gtlv_load *gtlv, const uint8_t *src_data, size_t src_data_len);

	/*! Write a TL to dst_data, and return the size of the TL written.
	 * This is also invoked by osmo_gtlv_put_update_tl() to overwrite a previous TL header. If the TL part's size
	 * can be different than the first time (e.g. due to a large L value in a TvLV protocol), an implementation can
	 * use the 'gtlv' arg to figure out how to memmove the message data:
	 * When invoked by osmo_gtlv_put_tl(), dst_data == gtlv->dst->tail and dst_data_avail == msgb_tailroom().
	 * When invoked by osmo_gtlv_put_update_tl(), dst_data < gtlv->dst->tail, dst_data points at the start of the
	 * TL section written earlier by osmo_gtlv_put_tl() and dst_data_avail == the size of the TL written earlier.
	 *
	 * \param dst_data  Write TL data to the start of this buffer.
	 * \param dst_data_avail  Remaining available space in dst_data.
	 * \param tag  The T value to store in dst_data.
	 * \param instance  The I value to store in dst_data (if this tag is a TLIV); ignore when not a TLIV.
	 * \param len  The L value to store in dst_data.
	 * \param gtlv  Backpointer to the osmo_gtlv_put struct, including gtlv->dst, the underlying msgb.
	 * \return the size of the TL part in bytes on success, -EINVAL if tag is invalid, -EMSGSIZE if len is too large
	 * or dst_data_avail is too small for the TL.
	 */
	int (*store_tl)(uint8_t *dst_data, size_t dst_data_avail, const struct osmo_gtlv_tag_inst *ti, size_t len,
			struct osmo_gtlv_put *gtlv);
};

/*! Configuration that allows parsing an 8bit tag and 8bit length TLV. */
extern const struct osmo_gtlv_cfg osmo_t8l8v_cfg;

/*! Configuration that allows parsing a 16bit tag and 16bit length TLV (see for example PFCP). */
extern const struct osmo_gtlv_cfg osmo_t16l16v_cfg;

/*! State for loading a TLV structure from raw data. */
struct osmo_gtlv_load {
	/*! Caller-defined context pointer available for use by load_tl() and store_tl() implementations. */
	void *priv;

	/*! Definition of tag and length sizes (by function pointers). */
	const struct osmo_gtlv_cfg *cfg;

	/*! Overall message buffer being parsed. */
	struct {
		const uint8_t *data;
		size_t len;
	} src;

	/*! Return value from last invocation of osmo_gtlv_load_next*(): tag value of parsed IE. */
	struct osmo_gtlv_tag_inst ti;
	/*! Return value from last invocation of osmo_gtlv_load_next*(): Start of the IE's payload data (after tag and
	 * length). If the end of the src buffer is reached, val == NULL. If a TLV contained no value part, len == 0,
	 * but this still points just after the TL. */
	const uint8_t *val;
	/*! Return value from last invocation of osmo_gtlv_load_next*(): Length of the IE's payload data (without tag and
	 * length) */
	size_t len;
};

/* Start or restart the gtlv from the first IE in the overall TLV data. */
static inline void osmo_gtlv_load_start(struct osmo_gtlv_load *gtlv)
{
	gtlv->val = NULL;
}

int osmo_gtlv_load_next(struct osmo_gtlv_load *gtlv);
int osmo_gtlv_load_peek_tag(const struct osmo_gtlv_load *gtlv, struct osmo_gtlv_tag_inst *ti);
int osmo_gtlv_load_next_by_tag(struct osmo_gtlv_load *gtlv, unsigned int tag);
int osmo_gtlv_load_next_by_tag_inst(struct osmo_gtlv_load *gtlv, const struct osmo_gtlv_tag_inst *ti);

/* State for storing a TLV structure into a msgb. */
struct osmo_gtlv_put {
	/*! Caller-defined context pointer available for use by load_tl() and store_tl() implementations. */
	void *priv;

	/* Definition of tag and length sizes (by function pointers). */
	const struct osmo_gtlv_cfg *cfg;

	/* msgb to append new TL to */
	struct msgb *dst;
	/* What was the last TL written and where are its TL and V */
	struct osmo_gtlv_tag_inst last_ti;
	uint8_t *last_tl;
	uint8_t *last_val;
};

int osmo_gtlv_put_tl(struct osmo_gtlv_put *gtlv, unsigned int tag, size_t len);
int osmo_gtlv_put_tli(struct osmo_gtlv_put *gtlv, const struct osmo_gtlv_tag_inst *ti, size_t len);
int osmo_gtlv_put_update_tl(struct osmo_gtlv_put *gtlv);
