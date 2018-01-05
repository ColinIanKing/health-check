/*
 * Copyright (C) 2013-2018 Canonical, Ltd.
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

#include "list.h"
#include "json.h"
#include "event.h"
#include "health-check.h"

static list_t event_info_start, event_info_finish;
static bool timer_stats = true;

/*
 *  event_timer_stat_set()
 *	enable/disable timer stat
 */
static int event_timer_stat_set(const char *str)
{
	FILE *fp;

	if ((fp = fopen(TIMER_STATS, "w")) == NULL)
		return -1;
	fprintf(fp, "%s\n", str);
	(void)fclose(fp);

	return 0;
}

/*
 *  event_free()
 *	free event info
 */
static void event_free(void *data)
{
	event_info_t *ev = (event_info_t *)data;

	free(ev->func);
	free(ev->callback);
	free(ev->ident);
	free(ev);
}

/*
 *  event_cmp()
 *	compare event info for sorting
 */
static int event_cmp(const void *data1, const void *data2)
{
	const event_info_t *ev1 = (const event_info_t *)data1;
	const event_info_t *ev2 = (const event_info_t *)data2;

	return ev2->count - ev1->count;
}

/*
 *  event_add()
 *	add event stats
 */
static int event_add(
	list_t *events,			/* event list */
	const uint64_t count,		/* event count */
	const pid_t pid,		/* PID of task */
	const char *func,		/* Kernel function */
	const char *callback)		/* Kernel timer callback */
{
	char ident[4096];
	event_info_t	*ev;
	link_t *l;
	proc_info_t	*p;

	/* Does it exist? */
	if ((p = proc_cache_find_by_pid(pid)) == NULL)
		return 0;

	snprintf(ident, sizeof(ident), "%d:%s:%s:%s", pid, p->comm, func, callback);

	for (l = events->head; l; l = l->next) {
		ev = (event_info_t *)l->data;
		if (strcmp(ev->ident, ident) == 0) {
			ev->count += count;
			return 0;
		}
	}

	/* Not found, it is new! */

	if ((ev = calloc(1, sizeof(event_info_t))) == NULL) {
		health_check_out_of_memory("allocting event information");
		return -1;
	}

	ev->proc = p;
	ev->func = strdup(func);
	ev->callback = strdup(callback);
	ev->ident = strdup(ident);
	ev->count = count;

	if (ev->func == NULL || ev->callback == NULL || ev->ident == NULL) {
		health_check_out_of_memory("allocting event information");
		goto err;
	}

	if (list_add_ordered(events, ev, event_cmp) == NULL)
		goto err;

	return 0;
err:
	free(ev->func);
	free(ev->callback);
	free(ev->ident);
	free(ev);

	return -1;
}

/*
 *  event_get_all_pids()
 *	scan /proc/timer_stats and populate a timer stat hash table with
 *	unique events
 */
int event_get_all_pids(const list_t *pids, proc_state state)
{
	FILE *fp;
	char buf[4096];
	list_t *events = (state == PROC_START) ? &event_info_start : &event_info_finish;

	if ((fp = fopen(TIMER_STATS, "r")) == NULL) {
		fprintf(stderr, "Cannot open %s.\n", TIMER_STATS);
		return 0;
	}

	while (!feof(fp)) {
		char *ptr = buf;
		uint64_t count = 0;
		pid_t event_pid = -1;
		char func[128];
		char timer[128];
		link_t *l;

		if (fgets(buf, sizeof(buf), fp) == NULL)
			break;

		if (strstr(buf, "total events") != NULL)
			break;

		if (strstr(buf, ",") == NULL)
			continue;

		/* format: count[D], pid, comm, func (timer) */

		while (*ptr && *ptr != ',')
			ptr++;

		if (*ptr != ',')
			continue;

		if (ptr > buf && *(ptr-1) == 'D')
			continue;	/* Deferred event, skip */

		ptr++;
		sscanf(buf, "%" SCNu64, &count);
		sscanf(ptr, "%8d", &event_pid);
		sscanf(ptr + 24, "%127s (%127[^)])", func, timer);

		for (l = pids->head; l; l = l->next) {
			proc_info_t *p = (proc_info_t *)l->data;
			if (event_pid == p->pid) {
				if (event_add(events, count, event_pid, func, timer) < 0) {
					(void)fclose(fp);
					return -1;
				}
				break;
			}
		}
	}

	(void)fclose(fp);

	return 0;
}

/*
 *  event_loading()
 *
 */
static const char *event_loading(const double wakeup_rate)
{
	if (FLOAT_CMP(wakeup_rate, 0.0))
		return "idle";
	if (wakeup_rate > 200.0)
		return "very excessive";
	if (wakeup_rate > 60.0)
		return "excessive";
	if (wakeup_rate > 20.0)
		return "very high";
	if (wakeup_rate > 10.0)
		return "high";
	if (wakeup_rate > 5.0)
		return "quite high";
	if (wakeup_rate > 1.0)
		return "moderate";
	if (wakeup_rate > 0.25)
		return "low";
	return "very low";
}

/*
 *  event_delta()
 *	find delta in events between old, new.
 *	if no old then delta is the new.
 */
static uint64_t event_delta(const event_info_t *event_new, const list_t *events_old)
{
	link_t *l;

	for (l = events_old->head; l; l = l->next) {
		event_info_t *event_old = (event_info_t*)l->data;
		if (strcmp(event_new->ident, event_old->ident) == 0)
			return event_new->count - event_old->count;
	}
	return event_new->count;
}


/*
 *  event_dump_diff()
 *	dump differences between old and new events
 */
void event_dump_diff(
	json_object *j_tests,
	const double duration)
{
	link_t *l;
#ifndef JSON_OUTPUT
	(void)j_tests;
#endif

	printf("Wakeups:\n");

	if (event_info_finish.head) {
		if (opt_flags & OPT_BRIEF) {
			double event_rate = 0.0;
			for (l = event_info_finish.head; l; l = l->next) {
				event_info_t *event_new = (event_info_t *)l->data;
				uint64_t delta = event_delta(event_new, &event_info_start);
				event_rate += (double)delta;
			}
			event_rate /= duration;
			printf(" %.2f wakeups/sec (%s)\n\n",
				event_rate, event_loading(event_rate));
		} else {
			int count = 0;
			double total = 0.0;
			const int pid_size = pid_max_digits();

			printf(" %*s Process               Wake/Sec Kernel Functions\n",
				pid_size, "PID");
			for (l = event_info_finish.head; l; l = l->next) {
				event_info_t *event_new = (event_info_t *)l->data;
				uint64_t delta = event_delta(event_new, &event_info_start);
				double event_rate = (double)delta / duration;

				printf(" %*d %-20.20s %9.2f (%s, %s) (%s)\n",
					pid_size, event_new->proc->pid,
					event_new->proc->cmdline,
					event_rate,
					event_new->func, event_new->callback,
					event_loading(event_rate));
				total += event_rate;
				count++;
			}
			if (count > 1)
				printf(" %-27.27s%9.2f\n", "Total",
					total);
			printf("\n");
		}
	} else {
		printf(" No wakeups detected%s.\n\n",
			timer_stats ? "" : " (Access to " TIMER_STATS " failed)");
	}

#ifdef JSON_OUTPUT
	if (j_tests) {
		json_object *j_event_test, *j_events, *j_event;
		uint64_t total_delta = 0;
		double total_event_rate;

		if ((j_event_test = j_obj_new_obj()) == NULL)
			goto out;
		j_obj_obj_add(j_tests, "wakeup-events", j_event_test);
		if ((j_events = j_obj_new_array()) == NULL)
			goto out;
		j_obj_obj_add(j_event_test, "wakeup-events-per-process", j_events);

		for (l = event_info_finish.head; l; l = l->next) {
			event_info_t *event = (event_info_t *)l->data;
			uint64_t delta = event_delta(event, &event_info_start);
			double event_rate = (double)delta / duration;
			total_delta += delta;

			/* We may as well dump everything */
			if ((j_event = j_obj_new_obj()) == NULL)
				goto out;
			j_obj_new_int32_add(j_event, "pid", event->proc->pid);
			j_obj_new_int32_add(j_event, "ppid", event->proc->ppid);
			j_obj_new_int32_add(j_event, "is-thread", event->proc->is_thread);
			j_obj_new_string_add(j_event, "name", event->proc->cmdline);
			j_obj_new_string_add(j_event, "kernel-timer-func", event->func);
			j_obj_new_string_add(j_event, "kernel-timer-callback", event->callback);
			j_obj_new_int64_add(j_event, "wakeups", delta);
			j_obj_new_double_add(j_event, "wakeup-rate", event_rate);
			j_obj_new_string_add(j_event, "load-hint", event_loading(event_rate));
			j_obj_array_add(j_events, j_event);
		}

		total_event_rate = (double)total_delta / duration;
		if ((j_event = j_obj_new_obj()) == NULL)
			goto out;
		j_obj_obj_add(j_event_test, "wakeup-events-total", j_event);
		j_obj_new_int64_add(j_event, "wakeup-total", total_delta);
		j_obj_new_double_add(j_event, "wakeup-total-rate", total_event_rate);
		j_obj_new_string_add(j_event, "load-hint-total", event_loading(total_event_rate));
	}
out:
#endif
	return;
}

/*
 *  event_init()
 *	initialise events and start timer stat
 */
void event_init(void)
{
	list_init(&event_info_start);
	list_init(&event_info_finish);

	/* Should really catch signals and set back to zero before we die */
        if (event_timer_stat_set("1") < 0)
		timer_stats = false;
}

/*
 *  event_stop()
 *	stop event timer stat
 */
void event_stop(void)
{
	if (timer_stats)
        	event_timer_stat_set("0");
}

/*
 *  event_cleanup()
 *	free memory
 */
void event_cleanup(void)
{
	list_free(&event_info_start, event_free);
	list_free(&event_info_finish, event_free);
}
