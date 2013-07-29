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

#include <stdint.h>

/* wakeup event information per process */
typedef struct {
	proc_info_t	*proc;		/* Proc specific info */
	uint64_t	size;
} mem_info_t;

void mem_get(list_t *pids, list_t *mem);
void mem_dump_diff(const double duration, list_t *mem_old, list_t *mem_new);

#endif
