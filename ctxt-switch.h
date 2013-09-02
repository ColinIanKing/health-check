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
#ifndef __CTXT_SWITCH_H__
#define __CTXT_SWITCH_H__

#define _GNU_SOURCE

#include "json.h"
#include "proc.h"
#include "list.h"

/* context switch event information per process */
typedef struct {
	proc_info_t	*proc;		/* Proc specific info */
	uint64_t	voluntary;	/* Voluntary context switches */
	uint64_t	involuntary;	/* Unvoluntary context switches */
	uint64_t	total;		/* Total context switches */
} ctxt_switch_info_t;

extern void ctxt_switch_get(const list_t *pids, list_t *ctxt_switches);
extern void ctxt_switch_dump_diff(json_object *j_tests, const double duration, const list_t *events_old, const list_t *events_new);

#endif
