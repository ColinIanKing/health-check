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

#include "list.h"

/* fnotify file information per process */
typedef struct {
	proc_info_t	*proc;		/* Proc specific info */
	char		*filename;	/* Name of device or filename being accessed */
	int		mask;		/* fnotify access mask */
	unsigned 	count;		/* Count of accesses */
} fnotify_fileinfo_t;

/* fnotify I/O operations counts per process */
typedef struct {
	unsigned long 	open_total;	/* open() count */
	unsigned long 	close_total;	/* close() count */
	unsigned long 	read_total;	/* read() count */
	unsigned long 	write_total;	/* write() count */
	unsigned long 	total;		/* total count */
	proc_info_t   	*proc;		/* process information */
} io_ops_t;

extern int fnotify_event_init(void);
extern void fnotify_event_free(void *data);
extern void fnotify_event_add(list_t *pids, const struct fanotify_event_metadata *metadata, list_t *fnotify_files);
extern void fnotify_dump_events(const double duration, list_t *pids, list_t *fnotify_files);

#endif
