/*
 * Copyright (C) 2013-2014 Canonical
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

#ifndef __NET_H__
#define __NET_H__

#include "list.h"
#include "json.h"

extern int net_connection_pids(list_t *pids);
extern int net_connection_pid(const pid_t);
extern int net_connection_dump(json_object *j_tests, double duration);
extern void net_account_send(const pid_t pid, const int fd, size_t size);
extern void net_account_recv(const pid_t pid, const int fd, size_t size);
extern void net_connection_init(void);
extern void net_connection_cleanup(void);

#endif
