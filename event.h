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
#ifndef __EVENT_H__
#define __EVENT_H__

#define _GNU_SOURCE

#include "proc.h"
#include "list.h"

#define TIMER_STATS	"/proc/timer_stats"

/* wakeup event information per process */
typedef struct {
	proc_info_t	*proc;		/* Proc specific info */
	char		*func;		/* Kernel waiting func */
	char		*callback;	/* Kernel timer callback func */
	char		*ident;		/* Unique identity */
	unsigned long	count;		/* Number of events */
} event_info_t;

extern void timer_stat_set(const char *str, const bool carp);
extern void event_free(void *data);
extern void event_get(list_t *pids, list_t *events);
extern void event_dump_diff(const double duration, list_t *events_old, list_t *events_new);
extern void event_init(void);
extern void event_deinit(void);

#endif
