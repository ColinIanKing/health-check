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
#ifndef __MEM_H__
#define __MEM_H__

#define _GNU_SOURCE

#include "proc.h"
#include "list.h"
#include "json.h"

#include <stdint.h>

typedef enum {
	MEM_STACK = 0,
	MEM_HEAP,
	MEM_MAPPED,
	MEM_MAX,
} mem_type_t;


/* wakeup event information per process */
typedef struct mem_info_t {
	proc_info_t	*proc;		/* Proc specific info */
	int64_t		size[MEM_MAX];
	int64_t		rss[MEM_MAX];
	int64_t		pss[MEM_MAX];
	int64_t		total[MEM_MAX];
} mem_info_t;

typedef struct {
	pid_t		pid;
	void		*brk_start;
	void		*brk_current;
	uint64_t	brk_count;
} mem_brk_info_t;

extern void mem_init(void);
extern void mem_cleanup(void);
extern void mem_get_all_pids(const list_t *pids, const proc_state state);
extern void mem_get_by_proc(proc_info_t *p, const proc_state state);
extern void mem_brk_account(const pid_t pid, void *addr);
extern void mem_dump_brk(json_object *j_tests, const double duration);

extern void mem_get(const list_t *pids, list_t *mem);
extern void mem_dump_diff(json_object *j_tests, const double duration);


#endif
