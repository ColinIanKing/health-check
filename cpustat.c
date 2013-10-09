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
#include <stdint.h>
#include <inttypes.h>
#include <unistd.h>
#include <limits.h>
#include <sys/time.h>

#include "list.h"
#include "json.h"
#include "cpustat.h"
#include "timeval.h"
#include "health-check.h"

static list_t cpustat_info_start, cpustat_info_finish;

/*
 *  cpustat_loading()
 *	map CPU loading to some human understandable form
 */
static const char *cpustat_loading(const double cpu_percent)
{
	if (cpu_percent == 0.0)
		return "idle";
	if (cpu_percent > 99.0)
		return "CPU fully loaded";
	if (cpu_percent > 95.0)
		return "nearly 1 CPU fully loaded";
	if (cpu_percent > 85.0)
		return "excessive load";
	if (cpu_percent > 70.0)
		return "very high load";
	if (cpu_percent > 40.0)
		return "high load";
	if (cpu_percent > 20.0)
		return "medium load";
	if (cpu_percent > 10.0)
		return "slight load";
	if (cpu_percent > 2.5)
		return "light load";
	return "very light load";
}

/*
 *  cpustat_cmp()
 *	cpu total time list sort comparitor
 */
static int cpustat_cmp(const void *data1, const void *data2)
{
	cpustat_info_t	*cpustat1 = (cpustat_info_t *)data1;
	cpustat_info_t	*cpustat2 = (cpustat_info_t *)data2;

	return cpustat2->ttime - cpustat1->ttime;
}

/*
 *  cpustat_dump_diff()
 *	dump difference in CPU loading between two snapshots in time
 */
int cpustat_dump_diff(json_object *j_tests, const double duration)
{
	double nr_ticks = (double)sysconf(_SC_CLK_TCK) * duration;
	double utime_total = 0.0, stime_total = 0.0, ttime_total = 0.0;
	int rc = 0;
	int count = 0;
	link_t *lo, *ln;
	list_t	sorted;
	cpustat_info_t *cio, *cin;
#ifndef JSON_OUTPUT
	(void)j_tests;
#endif
	list_init(&sorted);
	for (ln = cpustat_info_finish.head; ln; ln = ln->next) {
		cin = (cpustat_info_t*)ln->data;

		for (lo = cpustat_info_start.head; lo; lo = lo->next) {
			cio = (cpustat_info_t*)lo->data;

			if (cin->proc->pid == cio->proc->pid) {
				cpustat_info_t *cpustat;

				if ((cpustat = calloc(1, sizeof(*cpustat))) == NULL) {
					health_check_out_of_memory("cannot allocate cpustat information");
					goto out;
				}
				cpustat->proc  = cio->proc;
				cpustat->utime = cin->utime - cio->utime;
				cpustat->stime = cin->stime - cio->stime;
				cpustat->ttime = cin->ttime - cio->ttime;
				cpustat->duration = 
					timeval_to_double(&cin->whence) -
					timeval_to_double(&cio->whence);
				if (list_add_ordered(&sorted, cpustat, cpustat_cmp) == NULL) {
					free(cpustat);
					goto out;
				}

				/* We calculate this in terms of ticks and duration of each process */
				utime_total += (double)cpustat->utime / nr_ticks;
				stime_total += (double)cpustat->stime / nr_ticks;
				ttime_total += (double)cpustat->ttime / nr_ticks;
				count++;
			}
		}
	}

	printf("CPU usage:\n");
	if (sorted.head == NULL) {
		printf(" Nothing measured.\n");
	} else {
		if (opt_flags & OPT_BRIEF) {
			printf(" User: %6.2f%%, System: %6.2f%%, Total: %6.2f%% (%s)\n",
				100.0 * utime_total,
				100.0 * stime_total,
				100.0 * ttime_total,
				cpustat_loading(100.0 * (double)ttime_total));
		} else {
			printf("  PID  Process                USR%%   SYS%% TOTAL%%   Duration\n");
			for (ln = sorted.head; ln; ln = ln->next) {
				cin = (cpustat_info_t*)ln->data;
				printf(" %5d %-20.20s %6.2f %6.2f %6.2f   %8.2f  (%s)\n",
					cin->proc->pid,
					cin->proc->cmdline,
					100.0 * (double)cin->utime / nr_ticks,
					100.0 * (double)cin->stime / nr_ticks,
					100.0 * (double)cin->ttime / nr_ticks,
					cin->duration,
					cpustat_loading(100.0 * (double)cin->ttime / nr_ticks));
			}
			if (count > 1)
				printf(" %-26.26s %6.2f %6.2f %6.2f             (%s)\n",
					"Total",
					100.0 * utime_total,
					100.0 * stime_total,
					100.0 * ttime_total,
					cpustat_loading(100.0 * ttime_total));
		}
	}

#ifdef JSON_OUTPUT
	if (j_tests) {
		json_object *j_cpustat, *j_cpuload, *j_cpu;

		if ((j_cpustat = j_obj_new_obj()) == NULL)
			goto out;
		j_obj_obj_add(j_tests, "cpu-load", j_cpustat);
		if ((j_cpuload = j_obj_new_array()) == NULL)
			goto out;
		j_obj_obj_add(j_cpustat, "cpu-load-per-process", j_cpuload);

		for (ln = sorted.head; ln; ln = ln->next) {
			cin = (cpustat_info_t*)ln->data;

			if ((j_cpu = j_obj_new_obj()) == NULL)
				goto out;
			j_obj_new_int32_add(j_cpu, "pid", cin->proc->pid);
			j_obj_new_int32_add(j_cpu, "ppid", cin->proc->ppid);
			j_obj_new_int32_add(j_cpu, "is-thread", cin->proc->is_thread);
			j_obj_new_string_add(j_cpu, "name", cin->proc->cmdline);
			j_obj_new_int64_add(j_cpu, "user-cpu-ticks", cin->utime);
			j_obj_new_int64_add(j_cpu, "system-cpu-ticks", cin->stime);
			j_obj_new_int64_add(j_cpu, "total-cpu-ticks", cin->ttime);
			j_obj_new_double_add(j_cpu, "user-cpu-percent",
				100.0 * (double)cin->utime / nr_ticks);
			j_obj_new_double_add(j_cpu, "system-cpu-percent",
				100.0 * (double)cin->stime / nr_ticks);
			j_obj_new_double_add(j_cpu, "total-cpu-percent",
				100.0 * (double)cin->ttime / nr_ticks);
			j_obj_new_string_add(j_cpu, "load-hint",
				cpustat_loading(100.0 * (double)cin->ttime / nr_ticks));
			j_obj_array_add(j_cpuload, j_cpu);
		}

		if ((j_cpu = j_obj_new_obj()) == NULL)
			goto out;
		j_obj_obj_add(j_cpustat, "cpu-load-total", j_cpu);
		j_obj_new_double_add(j_cpu, "cpu-load-total", 100.0 * utime_total);
		j_obj_new_double_add(j_cpu, "user-cpu-percent", 100.0 * stime_total);
		j_obj_new_double_add(j_cpu, "system-cpu-percent", 100.0 * ttime_total);
	}
#endif
	printf("\n");
out:
	list_free(&sorted, free);

	return rc;
}

/*
 *  cpustat_get_by_proc()
 *	get CPU stats for a process
 */
int cpustat_get_by_proc(proc_info_t *proc, proc_state state)
{
	char filename[PATH_MAX];
	FILE *fp;
	list_t *cpustat = (state == PROC_START) ? &cpustat_info_start : &cpustat_info_finish;

	snprintf(filename, sizeof(filename), "/proc/%d/stat", proc->pid);
	if ((fp = fopen(filename, "r")) != NULL) {
		char comm[20];
		uint64_t utime, stime;
		pid_t pid;

		/* 3173 (a.out) R 3093 3173 3093 34818 3173 4202496 165 0 0 0 3194 0 */
		if (fscanf(fp, "%d (%[^)]) %*c %*d %*d %*d %*d %*d %*u %*u %*u %*u %*u %" SCNu64 " %" SCNu64,
			&pid, comm, &utime, &stime) == 4) {
			cpustat_info_t *info;

			info = calloc(1, sizeof(*info));
			if (info == NULL) {
				health_check_out_of_memory("allocating cpustat information");
				fclose(fp);
				return -1;
			}
			info->proc  = proc;
			info->utime = utime;
			info->stime = stime;
			info->ttime = utime + stime;
			gettimeofday(&info->whence, NULL);
			info->duration = 0.0;
			if (list_append(cpustat, info) == NULL) {
				free(info);
				fclose(fp);
				return -1;
			}
		}
		fclose(fp);
	}
	return 0;
}

/*
 *  cpustat_get_all_pids()
 *	get CPU stats for all processes
 */
int cpustat_get_all_pids(const list_t *pids, proc_state state)
{
	link_t *l;

	for (l = pids->head; l; l = l->next) {
		proc_info_t *p = (proc_info_t *)l->data;

		if (p->is_thread)
			continue;

		if (cpustat_get_by_proc(p, state) < 0)
			return -1;
	}
	return 0;
}

/*
 *  cpustat_init()
 *	initialize cpustat lists
 */
void cpustat_init(void)
{
	list_init(&cpustat_info_start);
	list_init(&cpustat_info_finish);
}

/*
 *  cpustat_cleanup()
 *	free cpustat lists
 */
void cpustat_cleanup(void)
{
	list_free(&cpustat_info_start, free);
	list_free(&cpustat_info_finish, free);
}
