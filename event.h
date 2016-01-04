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
#ifndef __EVENT_H__
#define __EVENT_H__

#define _GNU_SOURCE

#include "json.h"
#include "proc.h"
#include "list.h"

#define TIMER_STATS	"/proc/timer_stats"

#if (defined(__x86_64__) || defined(__i386__) || defined(__arm__))
#define EVENT_SUPPORTED	1
#else
#define EVENT_SUPPORTED 0
#endif


/* wakeup event information per process */
typedef struct {
	proc_info_t	*proc;		/* Proc specific info */
	char		*func;		/* Kernel waiting func */
	char		*callback;	/* Kernel timer callback func */
	char		*ident;		/* Unique identity */
	uint64_t	count;		/* Number of events */
} event_info_t;

extern int event_get_all_pids(const list_t *pids, proc_state state);
extern void event_dump_diff(json_object *j_tests, const double duration);
extern void event_stop(void);
extern void event_init(void);
extern void event_cleanup(void);

#endif
