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
#ifndef __PID_H__
#define __PID_H__

#define _GNU_SOURCE

#include <stdbool.h>

#include "unistd.h"
#include "list.h"

extern char *get_pid_comm(const pid_t pid);
extern char *get_pid_cmdline(const pid_t pid);
extern bool pid_exists(const pid_t pid);
extern bool pid_list_find(pid_t pid, list_t *list);
extern int pid_list_get_children(list_t *pids);

#endif
