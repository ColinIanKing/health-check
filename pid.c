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
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <limits.h>
#include <libgen.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "pid.h"
#include "list.h"
#include "proc.h"

#include "alloc.h"

/*
 *  get_pid_comm
 *
 */
char *get_pid_comm(const pid_t pid)
{
	char buffer[4096];
	int fd;
	ssize_t ret;

	snprintf(buffer, sizeof(buffer), "/proc/%i/comm", pid);

	if ((fd = open(buffer, O_RDONLY)) < 0)
		return NULL;

	if ((ret = read(fd, buffer, sizeof(buffer))) <= 0) {
		close(fd);
		return NULL;
	}
	close(fd);
	buffer[ret-1] = '\0';

	return strdup(buffer);
}

/*
 *  get_pid_cmdline
 * 	get process's /proc/pid/cmdline
 */
char *get_pid_cmdline(const pid_t pid)
{
	char buffer[4096];
	char *ptr;
	int fd;
	ssize_t ret;

	snprintf(buffer, sizeof(buffer), "/proc/%i/cmdline", pid);

	if ((fd = open(buffer, O_RDONLY)) < 0)
		return NULL;

	if ((ret = read(fd, buffer, sizeof(buffer))) <= 0) {
		close(fd);
		return NULL;
	}
	close(fd);

	if (ret >= (ssize_t)sizeof(buffer))
		ret = sizeof(buffer) - 1;
	buffer[ret] = '\0';

	for (ptr = buffer; *ptr && (ptr < buffer + ret); ptr++) {
		if (*ptr == ' ')
			*ptr = '\0';
	}

	return strdup(basename(buffer));
}

/*
 *  pid_exists()
 *	true if given process with given pid exists
 */
bool pid_exists(const pid_t pid)
{
	char path[PATH_MAX];
	struct stat statbuf;

	snprintf(path, sizeof(path), "/proc/%i", pid);
	return stat(path, &statbuf) == 0;
}

/*
 *  pid_list_find()
 *	find a pid in the pid list
 */
bool pid_list_find(
	const pid_t pid,
	list_t *list)
{
	link_t *l;

	for (l = list->head; l; l = l->next) {
		proc_info_t *p = (proc_info_t*)l->data;
		if (p->pid == pid)
			return true;
	}
	return false;
}

/*
 *  pid_get_children()
 *	get all the children from the given pid, add
 *	to children list
 */
void pid_get_children(
	const pid_t pid,
	list_t *children)
{
	link_t *l;

	for (l = proc_cache_list.head; l; l = l->next) {
		proc_info_t *p = (proc_info_t*)l->data;
		if (p->ppid == pid) {
			list_append(children, p);
			pid_get_children(p->pid, children);
		}
	}
}

/*
 *  pid_list_get_children()
 *	get all the chindren in the given pid list
 *	and add this to the list
 */
void pid_list_get_children(list_t *pids)
{
	link_t *l;
	list_t children;
	proc_info_t *p;

	list_init(&children);

	for (l = pids->head; l; l = l->next) {
		p = (proc_info_t *)l->data;
		pid_get_children(p->pid, &children);
	}

	/*  Append the children onto the pid list */
	for (l = children.head; l; l = l->next) {
		p = (proc_info_t *)l->data;
		if (!pid_list_find(p->pid, pids))
			list_append(pids, p);
	}

	/*  Free the children list, not the data */
	list_free(&children, NULL);

	for (l = pids->head; l; l = l->next)
		p = (proc_info_t *)l->data;
}
