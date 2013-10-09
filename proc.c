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
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <dirent.h>
#include <ctype.h>

#include "list.h"
#include "pid.h"
#include "proc.h"
#include "net.h"
#include "health-check.h"

#define HASH_TABLE_SIZE (1997)

list_t proc_cache_list;
static proc_info_t *proc_cache_hash[HASH_TABLE_SIZE];
static pthread_mutex_t pids_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t proc_cache_mutex = PTHREAD_MUTEX_INITIALIZER;

/*
 *  proc_cache_hash_pid()
 *	hash a process id
 */
static inline unsigned long proc_cache_hash_pid(const pid_t pid)
{
	unsigned long h = (unsigned long)pid;

	return h % HASH_TABLE_SIZE;
}

/*
 *  proc_cache_add_at_hash_index()
 *	heler function to add proc info to the proc cache and list
 */
static proc_info_t *proc_cache_add_at_hash_index(
	const unsigned long h,
	const pid_t pid,
	const pid_t ppid,
	const bool is_thread)
{
	proc_info_t *p;

	if ((p = calloc(1, sizeof(*p))) == NULL) {
		health_check_out_of_memory("allocating proc cache");
		return NULL;
	}

	p->pid  = pid;
	p->ppid = ppid;
	p->cmdline = get_pid_cmdline(pid);
	p->comm = get_pid_comm(pid);
	p->is_thread = is_thread;

	pthread_mutex_lock(&proc_cache_mutex);
	if (list_append(&proc_cache_list, p) == NULL) {
		pthread_mutex_unlock(&proc_cache_mutex);
		free(p->cmdline);
		free(p);
		return NULL;
	}
	p->next = proc_cache_hash[h];
	proc_cache_hash[h] = p;
	pthread_mutex_unlock(&proc_cache_mutex);

	return p;
}

/*
 *  proc_cache_add()
 *	explicity add process info to global cache ONLY if it is a traceable process
 */
proc_info_t *proc_cache_add(const pid_t pid, const pid_t ppid, const bool is_thread)
{
	proc_info_t *p;
	unsigned long h;

	if (!pid_exists(pid) || (pid == getpid()))
		return NULL;

	pthread_mutex_lock(&proc_cache_mutex);
	h = proc_cache_hash_pid(pid);
	for (p = proc_cache_hash[h]; p; p = p->next) {
		if (p->pid == pid) {
			pthread_mutex_unlock(&proc_cache_mutex);
			return p;
		}
	}
	pthread_mutex_unlock(&proc_cache_mutex);

	return proc_cache_add_at_hash_index(h, pid, ppid, is_thread);
}

/*
 *  proc_cache_find_by_pid()
 *	find process info by the process id, if it is not found
 * 	and it is a traceable process then cache it
 */
proc_info_t *proc_cache_find_by_pid(const pid_t pid)
{
	unsigned long h;
	proc_info_t *p;

	pthread_mutex_lock(&proc_cache_mutex);
	h = proc_cache_hash_pid(pid);
	for (p = proc_cache_hash[h]; p; p = p->next) {
		if (p->pid == pid) {
			pthread_mutex_unlock(&proc_cache_mutex);
			return p;
		}
	}
	pthread_mutex_unlock(&proc_cache_mutex);

	/*
	 *  Not found, so add it and return it if it is a legitimate
	 *  process to trace
	 */
	if (!pid_exists(pid) || (pid == getpid()))
		return NULL;

	/*  Be lazy and ignore the parent info lookup */
	return proc_cache_add_at_hash_index(h, pid, 0, false);
}

/*
 *  proc_cache_get()
 *	load proc cache with current system process info
 */
int proc_cache_get(void)
{
	DIR *procdir;
	struct dirent *procentry;

	if ((procdir = opendir("/proc")) == NULL) {
		fprintf(stderr, "Cannot open directory /proc.\n");
		return -1;
	}

	/*
	 *   Gather pid -> ppid mapping
	 */
	while ((procentry = readdir(procdir)) != NULL) {
		FILE *fp;
		char path[PATH_MAX];

		if (!isdigit(procentry->d_name[0]))
			continue;

		snprintf(path, sizeof(path), "/proc/%s/stat", procentry->d_name);
		if ((fp = fopen(path, "r")) != NULL) {
			pid_t pid, ppid;
			char comm[64];
			/* 3173 (a.out) R 3093 3173 3093 34818 3173 4202496 165 0 0 0 3194 0 */
			if (fscanf(fp, "%d (%[^)]) %*c %i", &pid, comm, &ppid) == 3)
				(void)proc_cache_add(pid, ppid, false);
			fclose(fp);
		}
	}
	closedir(procdir);

	return 0;
}

/*
 *  proc_cache_get_pthreads()
 *	load proc cache with pthreads from current system process info
 */
int proc_cache_get_pthreads(void)
{
	DIR *procdir;
	struct dirent *procentry;

	if ((procdir = opendir("/proc")) == NULL) {
		fprintf(stderr, "Cannot open directory /proc.\n");
		return -1;
	}

	/*
	 *   Gather pid -> ppid mapping
	 */
	while ((procentry = readdir(procdir)) != NULL) {
		DIR *taskdir;
		struct dirent *taskentry;
		char path[PATH_MAX];
		pid_t ppid;

		if (!isdigit(procentry->d_name[0]))
			continue;

		ppid = atoi(procentry->d_name);

		snprintf(path, sizeof(path), "/proc/%i/task", ppid);

		if ((taskdir = opendir(path)) == NULL)
			continue;

		(void)proc_cache_add(ppid, 0, false);

		while ((taskentry = readdir(taskdir)) != NULL) {
			pid_t pid;
			if (!isdigit(taskentry->d_name[0]))
				continue;
			pid = atoi(taskentry->d_name);
			if (pid == ppid)
				continue;
			if (proc_cache_add(pid, ppid, true) == NULL) {
				closedir(taskdir);
				closedir(procdir);
				return -1;
			}
		}
		closedir(taskdir);
	}
	closedir(procdir);

	return 0;
}

/*
 *  proc_cache_info_free()
 *	free a proc cache item
 */
static void proc_cache_info_free(void *data)
{
	proc_info_t *p = (proc_info_t*)data;

	free(p->cmdline);
	free(p->comm);
	free(p);
}

/*
 *  proc_pids_add_proc()
 *	add a process to pid list if it is sensible
 */
int proc_pids_add_proc(list_t *pids, proc_info_t *p)
{
	int rc = 0;

	if (p->pid == 1) {
		fprintf(stderr, "Cannot run health-check on init. Aborting.\n");
		health_check_exit(EXIT_FAILURE);
	}
	if (p->pid == getpid()) {
		fprintf(stderr, "Cannot run health-check on itself. Aborting.\n");
		health_check_exit(EXIT_FAILURE);
	}
	pthread_mutex_lock(&pids_mutex);
	if (list_append(pids, p) == NULL)
		rc = -1;
	pthread_mutex_unlock(&pids_mutex);

	return rc;
}

/*
 *  proc_cache_find_by_procname()
 *	find process by process name (in cmdline)
 *	we don't do this often, so a linear search is fine
 */
int proc_cache_find_by_procname(
	list_t *pids,
	const char *procname)
{
	bool found = false;
	link_t *l;

	pthread_mutex_lock(&proc_cache_mutex);
	for (l = proc_cache_list.head; l; l = l->next) {
		proc_info_t *p = (proc_info_t *)l->data;

		if (p->cmdline && strcmp(p->cmdline, procname) == 0) {
			proc_pids_add_proc(pids, p);
			found = true;
		}
	}
	pthread_mutex_unlock(&proc_cache_mutex);

	if (!found) {
		fprintf(stderr, "Cannot find process %s.\n", procname);
		return -1;
	}

	return 0;
}

/*
 *  proc_cache_init()
 *	initialize proc cache
 */
void proc_cache_init(void)
{
	list_init(&proc_cache_list);
}

/*
 *  proc_cache_cleanup
 *	cleanup
 */
void proc_cache_cleanup(void)
{
	list_free(&proc_cache_list, proc_cache_info_free);
}
