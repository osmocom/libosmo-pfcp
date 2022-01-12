/* Definitions for decoded message IEs, to be used by the auto-generated myproto_ies_auto.c. */
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

#include <osmocom/core/utils.h>

enum myproto_msg_type {
	MYPROTO_MSGT_MOO = 1,
	MYPROTO_MSGT_GOO = 7,
};

extern const struct value_string myproto_msg_type_names[];

enum myproto_iei {
	MYPROTO_IEI_FOO = 1,
	MYPROTO_IEI_BAR,
	MYPROTO_IEI_BAZ,
	MYPROTO_IEI_REPEAT_INT,
	MYPROTO_IEI_REPEAT_STRUCT,
	MYPROTO_IEI_MOO_NEST,
	MYPROTO_IEI_VAL,
	MYPROTO_IEI_GOO_NEST,
};

extern const struct value_string myproto_iei_names[];

struct myproto_ie_bar {
	char str[23];
};

struct myproto_ie_baz {
	int v_int;
	bool v_bool;
};

enum myproto_repeat_enum {
	R_A,
	R_B,
	R_C,
};

extern const struct value_string myproto_repeat_enum_names[];

struct myproto_ie_repeat_struct {
	int v_int;
	bool v_bool;
	enum myproto_repeat_enum v_enum;
};
