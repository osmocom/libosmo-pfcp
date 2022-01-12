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

#include <stdio.h>
#include <errno.h>

#include <osmocom/core/application.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/msgb.h>

#include <osmocom/gtlv/gtlv.h>

void *ctx;

struct ie {
	int tag;
	const char *val;
};

/* write all IEs to a msgb */
struct msgb *test_tlv_enc(const struct osmo_gtlv_cfg *cfg, const struct ie *ies)
{
	const struct ie *ie;
	struct osmo_gtlv_put gtlv = {
		.cfg = cfg,
		.dst = msgb_alloc(1024, __func__),
	};

	for (ie = ies; ie->val; ie++) {
		/* put header without knowing length yet */
		OSMO_ASSERT(osmo_gtlv_put_tl(&gtlv, ie->tag, 0) == 0);
		/* put value data, as much as desired */
		msgb_put(gtlv.dst, osmo_hexparse(ie->val, gtlv.dst->tail, msgb_tailroom(gtlv.dst)));
		/* update header len from amount of written data */
		OSMO_ASSERT(osmo_gtlv_put_update_tl(&gtlv) == 0);
	}

	printf("- encoded: %s.\n", osmo_hexdump(gtlv.dst->data, gtlv.dst->len));
	return gtlv.dst;
}

/* read all IEs from the msgb, and verify that it matches the given list of IEs */
void test_tlv_dec(const struct osmo_gtlv_cfg *cfg, const struct ie *ies, struct msgb *msg)
{
	const struct ie *ie;
	struct osmo_gtlv_load gtlv = {
		.cfg = cfg,
		.src = { msg->data, msg->len },
	};

	printf("- decoding:\n");
	osmo_gtlv_load_start(&gtlv);

	for (ie = ies; ie->val; ie++) {
		int rc = osmo_gtlv_load_next(&gtlv);
		if (rc) {
			printf("  ERROR loading TLV structure: osmo_gtlv_load_next() rc = %d\n", rc);
			exit(1);
		}
		/* end of TLV structure? */
		if (!gtlv.val)
			break;
		printf("  T=%d L=%zu v=%s\n", gtlv.tag, gtlv.len, osmo_hexdump_nospc(gtlv.val, gtlv.len));
		if (gtlv.tag != ie->tag) {
			printf("  ERROR loading TLV structure: expected tag %d, got tag %d\n", ie->tag, gtlv.tag);
			exit(1);
		}
		if (strcmp(ie->val, osmo_hexdump_nospc(gtlv.val, gtlv.len))) {
			printf("  ERROR loading TLV structure: expected val %s, got val %s\n", ie->val,
			       osmo_hexdump_nospc(gtlv.val, gtlv.len));
			exit(1);
		}
	}
}

void test_tlv_peek(const struct osmo_gtlv_cfg *cfg, const struct ie *ies, struct msgb *msg)
{
	const struct ie *ie;
	struct osmo_gtlv_load gtlv = {
		.cfg = cfg,
		.src = { msg->data, msg->len },
	};

	printf("- peeking:\n");
	osmo_gtlv_load_start(&gtlv);

	ie = ies;
	while (1) {
		int rc;
		int next_tag = osmo_gtlv_load_peek_tag(&gtlv);
		if (next_tag == -ENOENT)
			printf("  peek T=-ENOENT\n");
		else
			printf("  peek T=%d\n", next_tag);

		if (ie->val && next_tag != ie->tag) {
			printf("  ERROR peeking tag: expected tag %d, got tag %d\n", ie->tag, next_tag);
			exit(1);
		}
		if (!ie->val && next_tag != -ENOENT) {
			printf("  ERROR peeking tag: expected -ENOENT, got tag %d\n", next_tag);
			exit(1);
		}

		if (next_tag == -ENOENT)
			break;

		/* go to the next TLV */
		rc = osmo_gtlv_load_next(&gtlv);
		if (rc) {
			printf("  ERROR loading TLV structure: osmo_gtlv_load_next() rc = %d\n", rc);
			exit(1);
		}
		if (ie->val)
			ie++;
	}
}

/* Decode TLV in random order, each time searching for a tag in the raw data */
void test_tlv_dec_by_tag(const struct osmo_gtlv_cfg *cfg, const struct ie *ies, struct msgb *msg)
{
	const struct ie *last_ie;
	const struct ie *ie;
	int rc;
	struct osmo_gtlv_load gtlv = {
		.cfg = cfg,
		.src = { msg->data, msg->len },
	};

	printf("- decoding in reverse order:\n");

	last_ie = ies;
	while (last_ie->val) last_ie++;
	last_ie--;

	for (ie = last_ie; ie >= ies; ie--) {
		/* each time, look from the beginning */
		osmo_gtlv_load_start(&gtlv);
		rc = osmo_gtlv_load_next_by_tag(&gtlv, ie->tag);
		if (rc) {
			printf("  ERROR loading TLV structure: osmo_gtlv_load_next_by_tag(%d) rc = %d\n", ie->tag, rc);
			exit(1);
		}
		if (!gtlv.val) {
			printf("  ERROR loading TLV structure: osmo_gtlv_load_next_by_tag(%d) returned NULL val\n",
			       ie->tag);
			exit(1);
		}
		if (gtlv.tag != ie->tag) {
			printf("  ERROR loading TLV structure: expected tag %d, got tag %d\n", ie->tag, gtlv.tag);
			exit(1);
		}
		if (strcmp(ie->val, osmo_hexdump_nospc(gtlv.val, gtlv.len))) {
			while (1) {
				printf("   (mismatch: T=%d L=%zu v=%s, checking for another occurrence of T=%d)\n",
				       gtlv.tag, gtlv.len, osmo_hexdump_nospc(gtlv.val, gtlv.len), gtlv.tag);
				rc = osmo_gtlv_load_next_by_tag(&gtlv, ie->tag);
				if (rc || !gtlv.val) {
					printf("  ERROR val not found\n");
					exit(1);
				}
				if (strcmp(ie->val, osmo_hexdump_nospc(gtlv.val, gtlv.len)) == 0) {
					break;
				}
			}
		}
		printf("  T=%d L=%zu v=%s\n", gtlv.tag, gtlv.len, osmo_hexdump_nospc(gtlv.val, gtlv.len));
	}

	printf("- decoding every second tag:\n");

	osmo_gtlv_load_start(&gtlv);
	for (ie = ies; ie->val; ie++) {
		/* skip one tag */
		ie++;
		if (!ie->val)
			break;

		rc = osmo_gtlv_load_next_by_tag(&gtlv, ie->tag);
		if (rc) {
			printf("  ERROR loading TLV structure: osmo_gtlv_load_next_by_tag(%d) rc = %d\n", ie->tag, rc);
			exit(1);
		}
		if (!gtlv.val) {
			printf("  ERROR loading TLV structure: osmo_gtlv_load_next_by_tag(%d) returned NULL val\n",
			       ie->tag);
			exit(1);
		}
		if (gtlv.tag != ie->tag) {
			printf("  ERROR loading TLV structure: expected tag %d, got tag %d\n", ie->tag, gtlv.tag);
			exit(1);
		}
		if (strcmp(ie->val, osmo_hexdump_nospc(gtlv.val, gtlv.len))) {
			while (1) {
				printf("   (mismatch: T=%d L=%zu v=%s, checking for another occurrence of T=%d)\n",
				       gtlv.tag, gtlv.len, osmo_hexdump_nospc(gtlv.val, gtlv.len), gtlv.tag);
				rc = osmo_gtlv_load_next_by_tag(&gtlv, ie->tag);
				if (rc || !gtlv.val) {
					printf("  ERROR val not found\n");
					exit(1);
				}
				if (strcmp(ie->val, osmo_hexdump_nospc(gtlv.val, gtlv.len)) == 0) {
					break;
				}
			}
		}
		printf("  T=%d L=%zu v=%s\n", gtlv.tag, gtlv.len, osmo_hexdump_nospc(gtlv.val, gtlv.len));
	}

	printf("- enforcing order: without restart, a past tag is not parsed again:\n");
	/* Try to read the first tag, expect that it isn't found because we're already halfway in the message data */
	ie = ies;
	rc = osmo_gtlv_load_next_by_tag(&gtlv, ie->tag);
	printf("  osmo_gtlv_load_next_by_tag(%d) rc=", ie->tag);
	if (rc == -ENOENT) {
		printf("-ENOENT\n");
	} else {
		printf("%d\n", rc);
		printf("  ERROR: expected -ENOENT\n");
		exit(1);
	}
}

void test_tlv(const char *label, struct ie *tests[], size_t tests_len, const struct osmo_gtlv_cfg *cfg)
{
	int i;
	for (i = 0; i < tests_len; i++) {
		const struct ie *ies = tests[i];
		struct msgb *msg;
		printf("\n=== start: %s[%d]\n", label, i);

		msg = test_tlv_enc(cfg, ies);
		test_tlv_dec(cfg, ies, msg);
		test_tlv_peek(cfg, ies, msg);
		test_tlv_dec_by_tag(cfg, ies, msg);

		msgb_free(msg);

		printf("=== end: %s[%d]\n", label, i);
	}
}

struct ie t8l8v_test1[] = {
	/* smallest T */
	{ 0, "2342" },
	/* largest T */
	{ 255, "2342" },

	/* smallest V (no V data) */
	{ 1, "" },
	/* largest V, 255 bytes is the largest that an 8bit size length can express. */
	{ 123, "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	       "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	       "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	       "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	       "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	       "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	       "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	       "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	},

	/* arbitrary test data */
	{ 101, "11" },
	{ 102, "2222" },
	{ 103, "333333" },
	{}
};

struct ie t8l8v_test_multi[] = {
	{ 42, "42" },
	{ 2, "0101" },
	{ 2, "2222" },
	{ 3, "11" },
	{ 3, "2222" },
	{ 3, "333333" },
	{ 23, "23" },
	{ 42, "666f72747974776f" },
	{ 23, "7477656e74797468726565" },
	{}
};

struct ie *t8l8v_tests[] = {
	t8l8v_test1,
	t8l8v_test_multi,
};

void test_t8l8v()
{
	test_tlv(__func__, t8l8v_tests, ARRAY_SIZE(t8l8v_tests), &osmo_t8l8v_cfg);
}

struct ie t16l16v_test1[] = {
	/* smallest T */
	{ 0, "2342" },
	/* largest T */
	{ 65535, "2342" },

	/* smallest V (no V data) */
	{ 1, "" },
	/* 256 bytes is one more than an 8bit size length can express. */
	{ 123, "0000000000000000000000000000000000000000000000000000000000000000"
	       "0000000000000000000000000000000000000000000000000000000000000000"
	       "0000000000000000000000000000000000000000000000000000000000000000"
	       "0000000000000000000000000000000000000000000000000000000000000000"
	       "0000000000000000000000000000000000000000000000000000000000000000"
	       "0000000000000000000000000000000000000000000000000000000000000000"
	       "0000000000000000000000000000000000000000000000000000000000000000"
	       "0000000000000000000000000000000000000000000000000000000000000000"
	},

	/* arbitrary test data */
	{ 1001, "11" },
	{ 1002, "2222" },
	{ 1003, "333333" },
	{}
};

struct ie t16l16v_test_multi[] = {
	{ 1042, "42" },
	{ 102, "0101" },
	{ 102, "2222" },
	{ 103, "11" },
	{ 103, "2222" },
	{ 103, "333333" },
	{ 1023, "23" },
	{ 1042, "666f72747974776f" },
	{ 1023, "7477656e74797468726565" },
	{}
};

struct ie *t16l16v_tests[] = {
	t16l16v_test1,
	t16l16v_test_multi,
};

void test_t16l16v()
{
	test_tlv(__func__, t16l16v_tests, ARRAY_SIZE(t16l16v_tests), &osmo_t16l16v_cfg);
}

struct ie txlxv_test1[] = {
	/* smallest T */
	{ 0, "2342" },
	/* largest T that still fits in one encoded octet (highest bit serves as flag) */
	{ 0x7f, "2342" },
	/* smallest T that needs two octets to be encoded (first octet = 0x80 flag + 0, second octet = 0x1) */
	{ 0x80, "2342" },
	/* largest T that can be encoded in 16bit - one flag bit. */
	{ 0x7fff, "2342" },

	/* smallest V (no V data) */
	{ 1, "" },
	/* 256 bytes is one more than an 8bit size length can express. */
	{ 123, "0000000000000000000000000000000000000000000000000000000000000000"
	       "0000000000000000000000000000000000000000000000000000000000000000"
	       "0000000000000000000000000000000000000000000000000000000000000000"
	       "0000000000000000000000000000000000000000000000000000000000000000"
	       "0000000000000000000000000000000000000000000000000000000000000000"
	       "0000000000000000000000000000000000000000000000000000000000000000"
	       "0000000000000000000000000000000000000000000000000000000000000000"
	       "0000000000000000000000000000000000000000000000000000000000000000"
	},

	/* arbitrary test data */
	{ 1002, "2222" },
	{ 1003, "333333" },
	{}
};

struct ie txlxv_test_multi[] = {
	{ 1042, "42" },
	{ 1002, "0101" },
	{ 1002, "2222" },
	{ 103, "11" },
	{ 103, "2222" },
	{ 103, "333333" },
	{ 1023, "23" },
	{ 1042, "666f72747974776f" },
	{ 1023, "7477656e74797468726565" },
	{}
};

struct ie *txlxv_tests[] = {
	txlxv_test1,
	txlxv_test_multi,
};

/* Example of defining a variable TL, where size of T and L depend on the actual tag and length values: load. */
int txlxv_load_tl(struct osmo_gtlv_load *gtlv, const uint8_t *src_data, size_t src_data_len)
{
	const uint8_t *pos = src_data;
	const uint8_t *end = src_data + src_data_len;
	if (pos[0] & 0x80) {
		if (pos + 2 > end)
			return -EINVAL;
		gtlv->tag = (((int)pos[1]) << 7) + (pos[0] & 0x7f);
		pos += 2;
	} else {
		gtlv->tag = pos[0];
		pos++;
	}

	switch (gtlv->tag) {
	case 1002:
		/* fixed-length IE */
		gtlv->len = 2;
		break;
	case 123:
		/* 16bit length IE */
		if (pos + 2 > end)
			return -EINVAL;
		gtlv->len = osmo_load16be(pos);
		pos += 2;
		break;
	default:
		/* 8bit length IE */
		if (pos + 1 > end)
			return -EINVAL;
		gtlv->len = *pos;
		pos++;
		break;
	}
	gtlv->val = pos;
	return 0;
}

/* Example of defining a variable TL, where size of T and L depend on the actual tag and length values: store. */
int txlxv_store_tl(uint8_t *dst_data, size_t dst_data_avail, unsigned int tag, size_t len, struct osmo_gtlv_put *gtlv)
{
	uint8_t *pos = dst_data;
	uint8_t *end = dst_data + dst_data_avail;
	if (tag < 0x80) {
		if (pos + 1 > end)
			return -ENOSPC;
		pos[0] = tag;
		pos++;
	} else {
		if (pos + 2 > end)
			return -ENOSPC;
		pos[0] = 0x80 + (tag & 0x7f);
		pos[1] = tag >> 7;
		pos += 2;
	}

	switch (tag) {
	case 1002:
		/* fixed-length IE, write no len */
		break;
	case 123:
		/* 16bit length IE */
		if (len > UINT16_MAX)
			return -ERANGE;
		if (pos + 2 > end)
			return -ENOSPC;
		osmo_store16be(len, pos);
		pos += 2;
		break;
	default:
		/* 8bit length IE */
		if (len > UINT8_MAX)
			return -ERANGE;
		if (pos + 1 > end)
			return -ENOSPC;
		pos[0] = len;
		pos++;
		break;
	}
	return pos - dst_data;
}

const struct osmo_gtlv_cfg txlxv_cfg = {
	.tl_min_size = 1,
	.load_tl = txlxv_load_tl,
	.store_tl = txlxv_store_tl,
};

void test_txlxv()
{
	test_tlv("txlxv_tests", txlxv_tests, ARRAY_SIZE(txlxv_tests), &txlxv_cfg);
}

int main()
{
	ctx = talloc_named_const(NULL, 0, "gtlv_test");
	msgb_talloc_ctx_init(ctx, 0);

	test_t8l8v();
	test_t16l16v();
	test_txlxv();

	talloc_free(ctx);
	return 0;
}
