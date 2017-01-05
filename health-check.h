/*
 * Copyright (C) 2013-2016 Canonical, Ltd.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 * Author: Colin Ian King <colin.king@canonical.com>
 */
#ifndef __HEALTH_CHECK_H__
#define __HEALTH_CHECK_H__

#define _GNU_SOURCE

#include <stdbool.h>
#include <math.h>
#include "json.h"

#define OPT_GET_CHILDREN                0x00000001
#define OPT_BRIEF                       0x00000002
#define OPT_ADDR_RESOLVE		0x00000004
#define OPT_WAKELOCKS_LIGHT             0x00000008
#define OPT_WAKELOCKS_HEAVY             0x00000010
#define OPT_VERBOSE                     0x00000020
#define OPT_FOLLOW_NEW_PROCS		0x00000040
#define OPT_DURATION			0x00000080

#define FLOAT_TINY			(0.0000001)
#define FLOAT_CMP(a, b)			(fabs((a) - (b)) < FLOAT_TINY)

extern void health_check_exit(const int status) __attribute__ ((noreturn));
extern void health_check_out_of_memory(const char *msg);
extern volatile bool keep_running;
extern long int opt_max_syscalls;
extern int opt_flags;

#endif
