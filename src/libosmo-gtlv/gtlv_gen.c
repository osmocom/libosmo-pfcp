/* Write h and c source files for TLV protocol definitions, based on very sparse TLV definitions.
 * For a usage example see tests/libosmo-gtlv/test_gtlv_gen/. */
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

#include <string.h>

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/utils.h>

#include <osmocom/gtlv/gtlv_gen.h>

static const struct osmo_gtlv_gen_cfg *g_cfg = NULL;

const struct osmo_gtlv_gen_ie osmo_gtlv_gen_ie_auto = {};

/* Helps avoid redundant definitions of the same type. */
struct seen_entry {
	struct llist_head entry;
	char str[256];
	const void *from_def;
};
static LLIST_HEAD(seen_list);

static bool seen(const char *str, const void *from_def)
{
	struct seen_entry *s;
	llist_for_each_entry(s, &seen_list, entry) {
		if (!strcmp(s->str, str)) {
			if (from_def != s->from_def) {
				fprintf(stderr, "ERROR: %s: multiple definitions use the same name: '%s'\n",
					g_cfg->proto_name, str);
				exit(1);
			}
			return true;
		}
	}
	s = talloc_zero(NULL, struct seen_entry);
	OSMO_STRLCPY_ARRAY(s->str, str);
	s->from_def = from_def;
	llist_add(&s->entry, &seen_list);
	return false;
}
static void clear_seen(void)
{
	struct seen_entry *s;
	while ((s = llist_first_entry_or_null(&seen_list, struct seen_entry, entry))) {
		llist_del(&s->entry);
		talloc_free(s);
	}
}

/* Return "struct foo_ie_bar" from g_cfg->decoded_type_prefix and ie. */
static inline const char *decoded_type(const struct osmo_gtlv_gen_ie_o *ie_o)
{
	static char b[255];
	const struct osmo_gtlv_gen_ie *ie = ie_o->ie;
	const char *tag_name;
	if (ie && ie->decoded_type)
		return ie->decoded_type;
	/* "struct foo_ie_" + "bar" = struct foo_ie_bar*/
	tag_name = ie ? ie->tag_name : NULL;
	snprintf(b, sizeof(b), "%s%s", g_cfg->decoded_type_prefix, tag_name ? : ie_o->name);
	return b;
}

/* --- .h file --- */

/* Write a listing of struct members like
 *     bool foo_present;
 *     int foo;
 *     struct myproto_ie_bar bar;
 *     struct abc abc[10];
 *     int abc_count;
 */
static void write_ie_members(const struct osmo_gtlv_gen_ie_o ies[])
{
	const struct osmo_gtlv_gen_ie_o *ie_o;
	for (ie_o = ies; ie_o->ie; ie_o++) {
		if (ie_o->optional)
			printf("\tbool %s_present;\n", ie_o->name);
		printf("\t%s %s", decoded_type(ie_o), ie_o->name);
		if (ie_o->multi) {
			printf("[%u];\n", ie_o->multi);
			printf("\tunsigned int %s_count", ie_o->name);
		}
		printf(";\n");
	}
}

/* Traverse nesting levels in the message definitions and generate the structs for all as needed. */
static void write_ie_auto_structs(const struct osmo_gtlv_gen_ie_o ies[])
{
	const struct osmo_gtlv_gen_ie_o *ie_o;
	if (!ies)
		return;
	for (ie_o = ies; ie_o->ie; ie_o++) {
		const struct osmo_gtlv_gen_ie *ie = ie_o->ie;
		if (!ie || !ie->nested_ies)
			continue;
		/* Recurse to write inner layers first, so that they can be referenced in outer layers. */
		write_ie_auto_structs(ie->nested_ies);

		/* Various IE definitions can use the same underlying type. Only generate each type once. */
		if (seen(decoded_type(ie_o), NULL))
			continue;

		/* Print:
		 *
		 * \* spec ref *\
		 * struct myproto_ie_goo {
		 *     bool foo_present;
		 *     int foo;
		 *     struct myproto_ie_bar bar;
		 *     struct abc abc[10];
		 *     int abc_count;
		 * };
		 */
		printf("\n");
		if (ie->spec_ref)
			printf("/* %s%s */\n", g_cfg->spec_ref_prefix, ie->spec_ref);
		printf("%s {\n", decoded_type(ie_o));
		write_ie_members(ie->nested_ies);
		printf("};\n");
	}
}

/* Write all auto-generated structs, starting with the outer message definitions and nesting into all contained IE
 * definitions. */
static void write_auto_structs(void)
{
	const struct osmo_gtlv_gen_msg *gen_msg;
	clear_seen();
	for (gen_msg = g_cfg->msg_defs; gen_msg->name; gen_msg++) {
		write_ie_auto_structs(gen_msg->ies);
	}
}

/* Write the struct definitions for each message, i.e. for each entry in the outer PDU's message union, as well as the
 * union itself.
 *
 * struct myproto_msg_foo {
 *    ...
 * }:
 * struct myproto_msg_goo {
 *    ...
 * };
 * union myproto_ies {
 *        myproto_msg_foo foo;
 *        myproto_msg_goo goo;
 * };
 */
static void write_msg_union(void)
{
	const struct osmo_gtlv_gen_msg *gen_msg;
	for (gen_msg = g_cfg->msg_defs; gen_msg->name; gen_msg++) {
		/* "struct foo_msg" + "_%s" { *
		 * struct foo_msg_goo_request { ... }; */
		printf("\nstruct %s_msg_%s {\n",
		       g_cfg->proto_name,
		       gen_msg->name);
		write_ie_members(gen_msg->ies);
		printf("};\n");
	}

	printf("\nunion %s_ies {\n", g_cfg->proto_name);
	for (gen_msg = g_cfg->msg_defs; gen_msg->name; gen_msg++) {
		printf("\tstruct %s_msg_%s %s;\n", g_cfg->proto_name,
		       gen_msg->name, gen_msg->name);
	}
	printf("};\n");
}

/* Write the C header, myproto_ies_auto.h */
static void write_h(void)
{
	printf("/* THIS FILE IS GENERATED FROM %s */\n", __FILE__);
	printf("#include <stdint.h>\n");
	printf("#include <osmocom/gtlv/gtlv_dec_enc.h>\n");
	if (g_cfg->h_header)
		printf("\n%s\n", g_cfg->h_header);
	write_auto_structs();
	write_msg_union();
	printf("\nconst struct osmo_gtlv_coding *%s_get_msg_coding(%s message_type);\n",
	       g_cfg->proto_name, g_cfg->message_type_enum ? : "int");
	printf("\n"
		"int %s_ies_decode(union %s_ies *dst, struct osmo_gtlv_load *gtlv, bool tlv_ordered,\n"
		"	%s message_type, osmo_gtlv_err_cb err_cb, void *err_cb_data, const struct value_string *iei_strs);\n",
		g_cfg->proto_name, g_cfg->proto_name, g_cfg->message_type_enum ? : "int");
	printf("\n"
		"int %s_ies_encode(struct osmo_gtlv_put *gtlv, const union %s_ies *src,\n"
		"	%s message_type, osmo_gtlv_err_cb err_cb, void *err_cb_data, const struct value_string *iei_strs);\n",
		g_cfg->proto_name, g_cfg->proto_name, g_cfg->message_type_enum ? : "int");
	printf("\n"
		"int %s_ies_encode_to_str(char *buf, size_t buflen, const union %s_ies *src,\n"
		"	%s message_type, const struct value_string *iei_strs);\n",
		g_cfg->proto_name, g_cfg->proto_name, g_cfg->message_type_enum ? : "int");
}

/* --- .c file --- */

/* Write a listing of:
 * extern int myproto_dec_foo(...);
 * extern int myproto_enc_foo(...);
 */
static void write_extern_dec_enc(const struct osmo_gtlv_gen_ie_o *ies)
{
	const struct osmo_gtlv_gen_ie_o *ie_o;
	for (ie_o = ies; ie_o->ie; ie_o++) {
		const struct osmo_gtlv_gen_ie *ie = ie_o->ie;
		const char *dec_enc = ie_o->name;
		if (ie)
			dec_enc = ie->dec_enc ? : (ie->tag_name ? : ie_o->name);
		if (ie && ie->nested_ies) {
			write_extern_dec_enc(ie->nested_ies);
			continue;
		}
		if (seen(dec_enc, NULL))
			continue;
		printf("extern int %s_dec_%s(void *decoded_struct, void *decode_to, const struct osmo_gtlv_load *gtlv);\n",
		       g_cfg->proto_name, dec_enc);
		printf("extern int %s_enc_%s(struct osmo_gtlv_put *gtlv, const void *decoded_struct, const void *encode_from);\n",
		       g_cfg->proto_name, dec_enc);
		if (g_cfg->add_enc_to_str)
			printf("extern int %s_enc_to_str_%s(char *buf, size_t buflen, const void *encode_from);\n",
			       g_cfg->proto_name, dec_enc);
	}
}

/* For a nested IE, write the struct osmo_gtlv_coding array of the inner IEs.
 * { { MYPROTO_IEI_BAR },
 *   .memb_ofs = offsetof(struct myproto_foo, bar),
 *   .dec_func = myproto_dec_bar,
 *   .enc_func = myproto_enc_bar,
 * },
 */
static void write_ies_array(const char *indent, const struct osmo_gtlv_gen_ie_o *ies, const char *obj_type, const char *substruct)
{
#define printi(FMT, ARGS...) printf("%s" FMT, indent, ##ARGS)

	const struct osmo_gtlv_gen_ie_o *ie_o;
	for (ie_o = ies; ie_o->ie; ie_o++) {
		const struct osmo_gtlv_gen_ie *ie = ie_o->ie;
		const char *tag_name = (ie && ie->tag_name) ? ie->tag_name : ie_o->name;
		printi("{ { %s%s", g_cfg->tag_prefix, osmo_str_toupper(tag_name));
		if (ie_o->instance)
			printf(", true, %s", ie_o->instance);
		printf(" },\n");
		printi("  .memb_ofs = offsetof(%s, %s%s),\n", obj_type, substruct, ie_o->name);
		if (ie->nested_ies) {
			printi("  .nested_ies = ies_in_%s,\n", tag_name);
		} else {
			const char *dec_enc = ie->dec_enc ? : (ie->tag_name ? : ie_o->name);
			printi("  .dec_func = %s_dec_%s,\n", g_cfg->proto_name, dec_enc);
			printi("  .enc_func = %s_enc_%s,\n", g_cfg->proto_name, dec_enc);
			if (g_cfg->add_enc_to_str)
				printi("  .enc_to_str_func = %s_enc_to_str_%s,\n", g_cfg->proto_name, dec_enc);
		}
		if (ie_o->multi) {
			printi("  .memb_array_pitch = OSMO_MEMB_ARRAY_PITCH(%s, %s%s),\n",
			       obj_type, substruct, ie_o->name);
			printi("  .has_count = true, .count_max = %u,\n", ie_o->multi);
			printi("  .count_mandatory = %u,\n", ie_o->multi_mandatory);
			printi("  .count_ofs = offsetof(%s, %s%s_count),\n", obj_type, substruct, ie_o->name);
		}
		if (ie_o->optional) {
			printi("  .has_presence_flag = true,\n");
			printi("  .presence_flag_ofs = offsetof(%s, %s%s_present),\n", obj_type, substruct, ie_o->name);
		}
		printi("},\n");
	}
}

/* For a nested IE, write the struct osmo_gtlv_coding array of the inner IEs.
 * static const struct osmo_gtlv_coding ies_in_foo[] = {
 *         { {MYPROTO_IEI_BAR},
 *           .memb_ofs = offsetof(struct myproto_foo, bar),
 *           .dec_func = myproto_dec_bar,
 *           .enc_func = myproto_enc_bar,
 *         },
 *         ...
 * };
 */
static void write_nested_ies_array(const struct osmo_gtlv_gen_ie_o *ies)
{
	const char *indent = "\t";
	const struct osmo_gtlv_gen_ie_o *ie_o;
	for (ie_o = ies; ie_o->ie; ie_o++) {
		const struct osmo_gtlv_gen_ie *ie = ie_o->ie;
		if (!ie || !ie->nested_ies)
			continue;
		write_nested_ies_array(ie->nested_ies);

		const char *ies_in_name = ie->tag_name ? : ie_o->name;
		if (seen(ies_in_name, ie))
			continue;

		printf("\nstatic const struct osmo_gtlv_coding ies_in_%s[] = {\n", ies_in_name);
		write_ies_array(indent, ie->nested_ies, decoded_type(ie_o), "");
		printi("{}\n");
		printf("};\n");
	}
}

/* Write the bulk of the C code: on the basis of the list of messages (g_cfg->msg_defs), write all dec/enc function
 * declarations, all IEs arrays as well as the list of message types, first triggering to write the C code for any inner
 * layers. */
static void write_c(void)
{
	const struct osmo_gtlv_gen_msg *gen_msg;

	printf("/* THIS FILE IS GENERATED FROM %s */\n", __FILE__);
	printf("#include <stddef.h>\n");
	printf("#include <errno.h>\n");
	printf("#include <osmocom/core/utils.h>\n");
	printf("#include <osmocom/gtlv/gtlv.h>\n");
	printf("#include <osmocom/gtlv/gtlv_dec_enc.h>\n");
	printf("#include <osmocom/gtlv/gtlv_gen.h>\n");
	if (g_cfg->c_header)
		printf("\n%s\n", g_cfg->c_header);

	printf("\n");
	clear_seen();
	for (gen_msg = g_cfg->msg_defs; gen_msg->name; gen_msg++) {
		write_extern_dec_enc(gen_msg->ies);
	}

	clear_seen();
	for (gen_msg = g_cfg->msg_defs; gen_msg->name; gen_msg++) {
		write_nested_ies_array(gen_msg->ies);
	}

	for (gen_msg = g_cfg->msg_defs; gen_msg->name; gen_msg++) {
		char *obj_type = talloc_asprintf(NULL, "union %s_ies", g_cfg->proto_name);
		char *substruct = talloc_asprintf(NULL, "%s.", gen_msg->name);
		printf("\nstatic const struct osmo_gtlv_coding ies_in_msg_%s[] = {\n", gen_msg->name);
		write_ies_array("\t", gen_msg->ies, obj_type, substruct);
		printf("\t{}\n};\n");
		talloc_free(substruct);
		talloc_free(obj_type);
	}
	printf("\nstatic const struct osmo_gtlv_coding *msg_defs[] = {\n");
	for (gen_msg = g_cfg->msg_defs; gen_msg->name; gen_msg++) {
		printf("\t[%s%s] = ies_in_msg_%s,\n", g_cfg->message_type_prefix, osmo_str_toupper(gen_msg->name), gen_msg->name);
	}
	printf("};\n");

	/* print this code snippet into the .c file, because only there can we do ARRAY_SIZE(foo_msg_coding). */
	printf("\n"
		"const struct osmo_gtlv_coding *%s_get_msg_coding(%s message_type)\n"
		"{\n"
		"	if (message_type >= ARRAY_SIZE(msg_defs))\n"
		"		return NULL;\n"
		"	return msg_defs[message_type];\n"
		"}\n",
		g_cfg->proto_name, g_cfg->message_type_enum ? : "int");

	printf("\n"
		"int %s_ies_decode(union %s_ies *dst, struct osmo_gtlv_load *gtlv, bool tlv_ordered,\n"
		"	%s message_type,\n"
		"	osmo_gtlv_err_cb err_cb, void *err_cb_data, const struct value_string *iei_strs)\n"
		"{\n"
		"	return osmo_gtlvs_decode(dst, sizeof(*dst), 0, gtlv, tlv_ordered, %s_get_msg_coding(message_type),\n"
		"		err_cb, err_cb_data, iei_strs);\n"
		"}\n",
		g_cfg->proto_name, g_cfg->proto_name, g_cfg->message_type_enum ? : "int", g_cfg->proto_name);
	printf("\n"
		"int %s_ies_encode(struct osmo_gtlv_put *gtlv, const union %s_ies *src,\n"
		"	%s message_type, osmo_gtlv_err_cb err_cb, void *err_cb_data, const struct value_string *iei_strs)\n"
		"{\n"
		"	return osmo_gtlvs_encode(gtlv, src, sizeof(*src), 0, %s_get_msg_coding(message_type),\n"
		"		err_cb, err_cb_data, iei_strs);\n"
		"}\n",
		g_cfg->proto_name, g_cfg->proto_name, g_cfg->message_type_enum ? : "int", g_cfg->proto_name);
	printf("\n"
		"int %s_ies_encode_to_str(char *buf, size_t buflen, const union %s_ies *src,\n"
		"	%s message_type, const struct value_string *iei_strs)\n"
		"{\n"
		"	return osmo_gtlvs_encode_to_str_buf(buf, buflen, src, sizeof(*src), 0, %s_get_msg_coding(message_type), iei_strs);\n"
		"}\n",
		g_cfg->proto_name, g_cfg->proto_name, g_cfg->message_type_enum ? : "int", g_cfg->proto_name);
}

/* Call this from your main(). */
int osmo_gtlv_gen_main(const struct osmo_gtlv_gen_cfg *cfg, int argc, const char **argv)
{
	if (argc < 2)
		return 1;

	g_cfg = cfg;

	if (strcmp(argv[1], "h") == 0)
		write_h();
	else if (strcmp(argv[1], "c") == 0)
		write_c();
	else
		return 1;

	clear_seen();
	return 0;
}
