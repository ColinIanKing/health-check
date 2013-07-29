/*
 * Copyright (C) 2013 Canonical
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
 */
#ifndef __HEALTH_CHECK_H__
#define __HEALTH_CHECK_H__

#define _GNU_SOURCE

#include <stdbool.h>

#define	OPT_GET_CHILDREN		0x00000001
#define OPT_BRIEF			0x00000002

extern void health_check_exit(const int status) __attribute__ ((noreturn));
extern volatile bool keep_running;
extern int opt_max_syscalls;
extern int opt_flags;

#endif
