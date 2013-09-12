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
#ifndef __FNOTIFY_H__
#define __FNOTIFY_H__

#define _GNU_SOURCE

#include <sys/fanotify.h>

#include "list.h"
#include "json.h"

/* fnotify file information per process */
typedef struct {
	proc_info_t	*proc;		/* Proc specific info */
	char		*filename;	/* Name of device or filename being accessed */
	unsigned int	mask;		/* fnotify access mask */
	uint64_t	count;		/* Count of accesses */
} fnotify_fileinfo_t;

/* fnotify wakelock accounting */
typedef struct {
	proc_info_t	*proc;		/* Proc specific info */
	uint64_t	locked;		/* Count of wake locks */
	uint64_t	unlocked;	/* Count of wake unlocks */
	uint64_t	total;		/* Total of wake locks and unlocks */
} fnotify_wakelock_info_t;

/* fnotify I/O operations counts per process */
typedef struct {
	uint64_t	open_total;	/* open() count */
	uint64_t	close_total;	/* close() count */
	uint64_t	read_total;	/* read() count */
	uint64_t	write_total;	/* write() count */
	uint64_t	total;		/* total count */
	proc_info_t   	*proc;		/* process information */
} io_ops_t;

extern int fnotify_event_init(void);
extern void fnotify_event_add(const list_t *pids, const struct fanotify_event_metadata *metadata, list_t *fnofify_wakelocks);
extern void fnotify_dump_events(json_object *j_tests, const double duration, const list_t *pids);
extern void fnotify_dump_wakelocks(json_object *j_tests, const double duration, const list_t *fnotify_wakelocks);
extern char *fnotify_get_filename(const pid_t pid, const int fd);

extern void fnotify_init(void);
extern void fnotify_cleanup(void);

#endif
