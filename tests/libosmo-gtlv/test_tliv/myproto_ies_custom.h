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
};

extern const struct value_string myproto_msg_type_names[];

enum myproto_iei {
	MYPROTO_IEI_BAR = 1,
};

enum myproto_iei_bar_inst {
	MYPROTO_IEI_BAR_ALPHA = 2,
	MYPROTO_IEI_BAR_BETA = 3,
	MYPROTO_IEI_BAR_GAMMA = 5,
};

extern const struct value_string myproto_iei_names[];

struct myproto_ie_bar {
	int a;
	bool b;
};
