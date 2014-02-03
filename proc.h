/*
 * Copyright (C) 2013-2014 Canonical, Ltd.
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
#ifndef __PROC_H__
#define __PROC_H__

#define _GNU_SOURCE

#include <unistd.h>
#include <pthread.h>
#include <stdbool.h>

#include "list.h"

typedef enum {
        PROC_START   = 0x00000001,
        PROC_FINISH  = 0x00000002
} proc_state;

/* process specific information */
typedef struct proc_info {
	pid_t		pid;		/* PID */
	pid_t		ppid;		/* Parent PID */
	char		*comm;		/* Kernel process comm name */
	char		*cmdline;	/* Process name from cmdline */
	bool		is_thread;	/* true if process is a thread */
	struct proc_info *next;		/* next in hash */
} proc_info_t;

extern list_t  proc_cache_list;

extern proc_info_t *proc_cache_add(const pid_t pid, const pid_t ppid, const bool is_thread);
extern proc_info_t *proc_cache_find_by_pid(pid_t pid);
extern int proc_cache_get(void);
extern int proc_cache_get_pthreads(void);
extern void proc_cache_dump(void);
extern int proc_cache_find_by_procname(list_t *pids, const char *procname);
extern int proc_pids_add_proc(list_t *pids, proc_info_t *p);
extern void proc_cache_init(void);
extern void proc_cache_cleanup(void);

#endif
