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

/*
 *  ctxt_switch_cmp()
 *	compare context switch info for sorting
 */
static int ctx_switch_cmp(const void *data1, const void *data2)
{
	ctxt_switch_info_t *c1 = (ctxt_switch_info_t *)data1;
	ctxt_switch_info_t *c2 = (ctxt_switch_info_t *)data2;

	return c2->total - c1->total;
}

static void ctxt_switch_read(const pid_t pid, ctxt_switch_info_t *info)
{
	char path[PATH_MAX];
	char buf[4096];
	FILE *fp;

	info->voluntary = 0;
	info->involuntary = 0;

	snprintf(path, sizeof(path), "/proc/%i/status", pid);

	if ((fp = fopen(path, "r")) == NULL)
		return;

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

	info->total = info->voluntary + info->involuntary;
	fclose(fp);
}

/*
 *  ctxt_switch_get()
 *	scan /proc/pid/status for context switch data
 */
void ctxt_switch_get(const list_t *pids, list_t *ctxt_switches)
{
	link_t *l;

	for (l = pids->head; l; l = l->next) {
		proc_info_t *p = (proc_info_t *)l->data;
		ctxt_switch_info_t *info;

		info = calloc(1, sizeof(*info));
		if (info == NULL) {
			fprintf(stderr, "Out of memory allocating context switch information.\n");
			health_check_exit(EXIT_FAILURE);
		}
		ctxt_switch_read(p->pid, info);
		info->proc = p;
		list_append(ctxt_switches, info);
	}
}

/*
 *  ctxt_switch_loading()
 *
 */
static const char *ctxt_switch_loading(const double rate)
{
	if (rate == 0.0)
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
			*total = ctxt_switch_new->total - ctxt_switch_old->total;
			*voluntary = ctxt_switch_new->voluntary - ctxt_switch_old->voluntary;
			*involuntary = ctxt_switch_new->involuntary -ctxt_switch_old->involuntary;
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
void ctxt_switch_dump_diff(
	json_object *j_tests,
	const double duration,
	const list_t *ctxt_switches_old,
	const list_t *ctxt_switches_new)
{
	link_t *l;
	list_t sorted;
#ifndef JSON_OUTPUT
	(void)j_tests;
#endif

	printf("Context Switches:\n");

	list_init(&sorted);
	for (l = ctxt_switches_new->head; l; l = l->next) {
		ctxt_switch_info_t *new_info, *info = (ctxt_switch_info_t *)l->data;

		new_info = calloc(1, sizeof(*info));
		if (new_info == NULL) {
			fprintf(stderr, "Out of memory allocating context switch information.\n");
			health_check_exit(EXIT_FAILURE);
		}
		new_info->proc = info->proc;
		ctxt_switch_delta(info, ctxt_switches_old,
			&new_info->total, &new_info->voluntary, &new_info->involuntary);
		list_add_ordered(&sorted, new_info, ctx_switch_cmp);
	}

	if (ctxt_switches_new->head) {
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

			printf("  PID  Process                Voluntary   Involuntary     Total\n");
			printf("                             Ctxt Sw/Sec  Ctxt Sw/Sec  Ctxt Sw/Sec\n");
			for (l = sorted.head; l; l = l->next) {
				ctxt_switch_info_t *info = (ctxt_switch_info_t *)l->data;

				printf(" %5d %-20.20s %12.2f %12.2f %12.2f (%s)\n",
					info->proc->pid, info->proc->cmdline,
					(double)info->voluntary / duration,
					(double)info->involuntary / duration,
					(double)info->total / duration,
					ctxt_switch_loading((double)info->total / duration));
				total_total += (double)info->total;
				total_voluntary += (double)info->voluntary;
				total_involuntary += (double)info->involuntary;
				count++;
			}
			if (count > 1)
				printf(" %-27.27s%12.2f %12.2f %12.2f\n", "Total",
					total_total / duration,
					total_voluntary / duration,
					total_involuntary / duration);
			printf("\n");
		}
	} else {
		printf(" No wakeups detected\n\n");
	}

#ifdef JSON_OUTPUT
	if (j_tests) {
		json_object *j_ctxt_switch_test, *j_ctxt_switches, *j_ctxt_switch;
		uint64_t total = 0;
		double total_rate;

		j_obj_obj_add(j_tests, "context-switches", (j_ctxt_switch_test = j_obj_new_obj()));
		j_obj_obj_add(j_ctxt_switch_test, "context-switches-per-process", (j_ctxt_switches = j_obj_new_array()));

		for (l = sorted.head; l; l = l->next) {
			ctxt_switch_info_t *info = (ctxt_switch_info_t *)l->data;
			total += info->total;

			j_ctxt_switch = j_obj_new_obj();
			j_obj_new_int32_add(j_ctxt_switch, "pid", info->proc->pid);
			j_obj_new_int32_add(j_ctxt_switch, "ppid", info->proc->ppid);
			j_obj_new_int32_add(j_ctxt_switch, "is-thread", info->proc->is_thread);
			j_obj_new_string_add(j_ctxt_switch, "name", info->proc->cmdline);
			j_obj_new_int64_add(j_ctxt_switch, "voluntary-context-switches", info->voluntary);
			j_obj_new_double_add(j_ctxt_switch, "voluntary-context-switch-rate", (double)info->voluntary / duration);
			j_obj_new_int64_add(j_ctxt_switch, "involuntary-context-switches", info->involuntary);
			j_obj_new_double_add(j_ctxt_switch, "involuntary-context-switch-rate", (double)info->involuntary / duration);
			j_obj_new_int64_add(j_ctxt_switch, "total-context-switches", info->total);
			j_obj_new_double_add(j_ctxt_switch, "total-context-switch-rate", (double)info->total / duration);
			j_obj_new_string_add(j_ctxt_switch, "load-hint", ctxt_switch_loading((double)info->total / duration));
			j_obj_array_add(j_ctxt_switches, j_ctxt_switch);
		}

		total_rate = (double)total / duration;
		j_obj_obj_add(j_ctxt_switch_test, "context-switches-total", (j_ctxt_switch = j_obj_new_obj()));
		j_obj_new_int64_add(j_ctxt_switch, "context-switch-total", total);
		j_obj_new_double_add(j_ctxt_switch, "context-switch-rate-total", total_rate);
		j_obj_new_string_add(j_ctxt_switch, "load-hint-total", ctxt_switch_loading(total_rate));
	}
#endif
	list_free(&sorted, free);
}