/*
 * Copyright (C) 2013-2017 Canonical, Ltd.
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
#define _GNU_SOURCE

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>

#include "list.h"
#include "json.h"
#include "ctxt-switch.h"
#include "health-check.h"

static list_t ctxt_switch_info_start, ctxt_switch_info_finish;

/*
 *  ctxt_switch_cmp()
 *	compare context switch info for sorting
 */
static int ctx_switch_cmp(const void *data1, const void *data2)
{
	const ctxt_switch_info_t *c1 = (const ctxt_switch_info_t *)data1;
	const ctxt_switch_info_t *c2 = (const ctxt_switch_info_t *)data2;

	return c2->total - c1->total;
}

/*
 *  ctxt_switch_get_by_proc()
 *	get context switch info for a specific process
 */
int ctxt_switch_get_by_proc(proc_info_t *proc, proc_state state)
{
	char path[PATH_MAX];
	char buf[4096];
	FILE *fp;
	ctxt_switch_info_t *info;
	list_t *ctxt_switches =
		(state == PROC_START) ? &ctxt_switch_info_start : &ctxt_switch_info_finish;

	snprintf(path, sizeof(path), "/proc/%i/status", proc->pid);
	if ((fp = fopen(path, "r")) == NULL)
		return 0;

	if ((info = calloc(1, sizeof(*info))) == NULL) {
		health_check_out_of_memory("allocating context switch information");
		(void)fclose(fp);
		return -1;
	}
	info->voluntary = 0;
	info->involuntary = 0;
	info->valid = false;
	info->proc = proc;

	while (!feof(fp)) {
		if (fgets(buf, sizeof(buf), fp) == NULL)
			break;
		if (!strncmp(buf, "voluntary_ctxt_switches:", 24)) {
			(void)sscanf(buf + 24, "%" SCNu64, &info->voluntary);
			continue;
		}
		if (!strncmp(buf, "nonvoluntary_ctxt_switches:", 27)) {
			(void)sscanf(buf + 27, "%" SCNu64, &info->involuntary);
			continue;
		}
	}
	(void)fclose(fp);
	info->total = info->voluntary + info->involuntary;
	info->valid = true;

	if (list_append(ctxt_switches, info) == NULL) {
		free(info);
		return -1;
	}

	return 0;
}

/*
 *  ctxt_switch_get_all_pids()
 *	scan /proc/pid/status for context switch data
 */
int ctxt_switch_get_all_pids(const list_t *pids, proc_state state)
{
	link_t *l;

	for (l = pids->head; l; l = l->next) {
		proc_info_t *p = (proc_info_t *)l->data;
		if (ctxt_switch_get_by_proc(p, state) < 0)
			return -1;
	}
	return 0;
}

/*
 *  ctxt_switch_loading()
 *	context switch rate to some human understandable text
 */
static const char *ctxt_switch_loading(const double rate)
{
	if (FLOAT_CMP(rate, 0.0))
		return "idle";
	if (rate > 10000.0)
		return "very high";
	if (rate > 1000.0)
		return "high";
	if (rate > 100.0)
		return "quite high";
	if (rate > 10.0)
		return "moderate";
	if (rate > 1.0)
		return "low";
	return "very low";
}

/*
 *  ctxt_switch_delta()
 *	find delta in context switches between old, new.
 *	if no old then delta is the new.
 */
static void ctxt_switch_delta(
	const ctxt_switch_info_t *ctxt_switch_new,
	const list_t *ctxt_switches_old,
	uint64_t *total,
	uint64_t *voluntary,
	uint64_t *involuntary)
{
	link_t *l;

	for (l = ctxt_switches_old->head; l; l = l->next) {
		ctxt_switch_info_t *ctxt_switch_old = (ctxt_switch_info_t*)l->data;
		if (ctxt_switch_new->proc == ctxt_switch_old->proc) {
			if (!ctxt_switch_old->valid)
				break;
			*total = ctxt_switch_new->total - ctxt_switch_old->total;
			*voluntary = ctxt_switch_new->voluntary - ctxt_switch_old->voluntary;
			*involuntary = ctxt_switch_new->involuntary - ctxt_switch_old->involuntary;
			return;
		}
	}

	*total = ctxt_switch_new->total;
	*voluntary = ctxt_switch_new->voluntary;
	*involuntary = ctxt_switch_new->involuntary;
}


/*
 *  ctxt_switch_dump_diff()
 *	dump differences between old and new events
 */
void ctxt_switch_dump_diff(json_object *j_tests, const double duration)
{
	link_t *l;
	list_t sorted;

#ifndef JSON_OUTPUT
	(void)j_tests;
#endif
	printf("Context Switches:\n");
	list_init(&sorted);
	for (l = ctxt_switch_info_finish.head; l; l = l->next) {
		ctxt_switch_info_t *new_info, *info = (ctxt_switch_info_t *)l->data;

		if (!info->valid)
			continue;

		if ((new_info = calloc(1, sizeof(*info))) == NULL) {
			health_check_out_of_memory("allocating context switch information");
			goto out;
		}
		new_info->proc = info->proc;
		ctxt_switch_delta(info,
			&ctxt_switch_info_start,
			&new_info->total,
			&new_info->voluntary,
			&new_info->involuntary);
		if (list_add_ordered(&sorted, new_info, ctx_switch_cmp) == NULL) {
			free(new_info);
			goto out;
		}
	}

	if (sorted.head) {
		if (opt_flags & OPT_BRIEF) {
			double rate = 0.0;

			for (l = sorted.head; l; l = l->next) {
				ctxt_switch_info_t *info = (ctxt_switch_info_t *)l->data;
				rate += (double)info->total;
			}
			rate /= duration;
			printf(" %.2f context switches/sec (%s)\n\n",
				rate, ctxt_switch_loading(rate));
		} else {
			int count = 0;
			double total_total = 0.0, total_voluntary = 0.0, total_involuntary = 0.0;
			const int pid_size = pid_max_digits();

			printf(" %*s Process                Voluntary   Involuntary     Total\n",
				pid_size, "PID");
			printf(" %*s                       Ctxt Sw/Sec  Ctxt Sw/Sec  Ctxt Sw/Sec\n",
				pid_size, "   ");
			for (l = sorted.head; l; l = l->next) {
				ctxt_switch_info_t *info = (ctxt_switch_info_t *)l->data;

				printf(" %*d %-20.20s %12.2f %12.2f %12.2f (%s)\n",
					pid_size, info->proc->pid,
					info->proc->cmdline,
					(double)info->voluntary / duration,
					(double)info->involuntary / duration,
					(double)info->total / duration,
					ctxt_switch_loading((double)info->total / duration));
				total_voluntary += (double)info->voluntary;
				total_involuntary += (double)info->involuntary;
				total_total += (double)info->total;
				count++;
			}
			if (count > 1)
				printf(" %-27.27s%12.2f %12.2f %12.2f\n", "Total",
					total_voluntary / duration,
					total_involuntary / duration,
					total_total / duration);
			printf("\n");
		}
	} else {
		printf(" No context switches detected.\n\n");
	}

#ifdef JSON_OUTPUT
	if (j_tests) {
		json_object *j_ctxt_switch_test, *j_ctxt_switches, *j_ctxt_switch;
		uint64_t total = 0;
		double total_rate;

		if ((j_ctxt_switch_test = j_obj_new_obj()) == NULL)
			goto out;
		j_obj_obj_add(j_tests, "context-switches", j_ctxt_switch_test);
		if ((j_ctxt_switches = j_obj_new_array()) == NULL)
			goto out;
		j_obj_obj_add(j_ctxt_switch_test, "context-switches-per-process", j_ctxt_switches);

		for (l = sorted.head; l; l = l->next) {
			ctxt_switch_info_t *info = (ctxt_switch_info_t *)l->data;

			total += (double)info->total;
			if ((j_ctxt_switch = j_obj_new_obj()) == NULL)
				goto out;
			j_obj_new_int32_add(j_ctxt_switch, "pid", info->proc->pid);
			j_obj_new_int32_add(j_ctxt_switch, "ppid", info->proc->ppid);
			j_obj_new_int32_add(j_ctxt_switch, "is-thread", info->proc->is_thread);
			j_obj_new_string_add(j_ctxt_switch, "name", info->proc->cmdline);
			j_obj_new_int64_add(j_ctxt_switch, "voluntary-context-switches", info->voluntary);
			j_obj_new_double_add(j_ctxt_switch, "voluntary-context-switch-rate", (double)info->voluntary / duration);
			j_obj_new_int64_add(j_ctxt_switch, "involuntary-context-switches", (double)info->involuntary / duration);
			j_obj_new_double_add(j_ctxt_switch, "involuntary-context-switch-rate", (double)info->involuntary / duration);
			j_obj_new_int64_add(j_ctxt_switch, "total-context-switches", info->total);
			j_obj_new_double_add(j_ctxt_switch, "total-context-switch-rate", (double)info->total / duration);
			j_obj_new_string_add(j_ctxt_switch, "load-hint", ctxt_switch_loading((double)info->total / duration));
			j_obj_array_add(j_ctxt_switches, j_ctxt_switch);
		}
		total_rate = (double)total / duration;
		if ((j_ctxt_switch = j_obj_new_obj()) == NULL)
			goto out;
		j_obj_obj_add(j_ctxt_switch_test, "context-switches-total", j_ctxt_switch);
		j_obj_new_int64_add(j_ctxt_switch, "context-switch-total", total);
		j_obj_new_double_add(j_ctxt_switch, "context-switch-total-rate", total_rate);
		j_obj_new_string_add(j_ctxt_switch, "load-hint-total", ctxt_switch_loading(total_rate));
	}
#endif

out:
	list_free(&sorted, free);
}

/*
 *  ctxt_switch_init()
 *	initialize lists
 */
void ctxt_switch_init(void)
{
	list_init(&ctxt_switch_info_start);
	list_init(&ctxt_switch_info_finish);
}

/*
 *  ctxt_switch_cleanup()
 *	cleanup lists
 */
void ctxt_switch_cleanup(void)
{
	list_free(&ctxt_switch_info_start, free);
	list_free(&ctxt_switch_info_finish, free);
}
