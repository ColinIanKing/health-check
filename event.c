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
#include <string.h>
#include <unistd.h>

#include "list.h"
#include "json.h"
#include "event.h"
#include "health-check.h"

/*
 *  event_timer_stat_set()
 *	enable/disable timer stat
 */
static void event_timer_stat_set(const char *str, const bool carp)
{
	FILE *fp;

	if ((fp = fopen(TIMER_STATS, "w")) == NULL) {
		if (carp) {
			fprintf(stderr, "Cannot write to %s\n",TIMER_STATS);
			exit(EXIT_FAILURE);
		} else {
			return;
		}
	}
	fprintf(fp, "%s\n", str);
	fclose(fp);
}

/*
 *  event_free()
 *	free event info
 */
void event_free(void *data)
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
	event_info_t *ev1 = (event_info_t *)data1;
	event_info_t *ev2 = (event_info_t *)data2;

	return ev2->count - ev1->count;
}

/*
 *  event_add()
 *	add event stats
 */
static void event_add(
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
		return;

	snprintf(ident, sizeof(ident), "%d:%s:%s:%s", pid, p->comm, func, callback);

	for (l = events->head; l; l = l->next) {
		ev = (event_info_t *)l->data;
		if (strcmp(ev->ident, ident) == 0) {
			ev->count += count;
			return;
		}
	}

	/* Not found, it is new! */

	if ((ev = calloc(1, sizeof(event_info_t))) == NULL) {
		fprintf(stderr, "Out of memory\n");
		health_check_exit(EXIT_FAILURE);
	}

	ev->proc = p;
	ev->func = strdup(func);
	ev->callback = strdup(callback);
	ev->ident = strdup(ident);
	ev->count = count;

	if (ev->proc == NULL ||
	    ev->func == NULL ||
	    ev->callback == NULL ||
	    ev->ident == NULL) {
		fprintf(stderr, "Out of memory\n");
		health_check_exit(EXIT_FAILURE);
	}

	list_add_ordered(events, ev, event_cmp);
}

/*
 *  event_get()
 *	scan /proc/timer_stats and populate a timer stat hash table with
 *	unique events
 */
void event_get(const list_t *pids, list_t *events)
{
	FILE *fp;
	char buf[4096];

	if ((fp = fopen(TIMER_STATS, "r")) == NULL) {
		fprintf(stderr, "Cannot open %s\n", TIMER_STATS);
		return;
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
		sscanf(ptr, "%d", &event_pid);
		sscanf(ptr + 24, "%s (%[^)])", func, timer);

		for (l = pids->head; l; l = l->next) {
			proc_info_t *p = (proc_info_t *)l->data;
			if (event_pid == p->pid) {
				event_add(events, count, event_pid, func, timer);
				break;
			}
		}
	}

	fclose(fp);
}

/*
 *  event_loading()
 *
 */
static const char *event_loading(const double wakeup_rate)
{
	if (wakeup_rate == 0.0)
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
	const double duration,
	const list_t *events_old,
	const list_t *events_new)
{
	link_t *l;

	printf("Wakeups:\n");

	if (events_new->head) {
		if (opt_flags & OPT_BRIEF) {
			double event_rate = 0.0;
			for (l = events_new->head; l; l = l->next) {
				event_info_t *event_new = (event_info_t *)l->data;
				uint64_t delta = event_delta(event_new, events_old);
				event_rate += (double)delta;
			}
			event_rate /= duration;
			printf(" %.2f wakeups/sec (%s)\n\n",
				event_rate, event_loading(event_rate));
			
		} else {
			int count = 0;
			double total = 0.0;

			printf("  PID  Process               Wake/Sec Kernel Functions\n");
			for (l = events_new->head; l; l = l->next) {
				event_info_t *event_new = (event_info_t *)l->data;
				uint64_t delta = event_delta(event_new, events_old);
				double event_rate = (double)delta / duration;
	
				printf(" %5d %-20.20s %9.2f (%s, %s) (%s)\n",
					event_new->proc->pid, event_new->proc->cmdline,
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
		printf(" No wakeups detected\n\n");
	}

	if (j_tests) {
		json_object *j_event_test, *j_events, *j_event;
		uint64_t total_delta = 0;
		double total_event_rate;

		j_obj_obj_add(j_tests, "wakeup-events", (j_event_test = j_obj_new_obj()));
		j_obj_obj_add(j_event_test, "wakeup-events-per-process", (j_events = j_obj_new_array()));

		for (l = events_new->head; l; l = l->next) {
			event_info_t *event = (event_info_t *)l->data;
			uint64_t delta = event_delta(event, events_old);
			double event_rate = (double)delta / duration;
			total_delta += delta;

			/* We may as well dump everything */
			j_event = j_obj_new_obj();
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
		j_obj_obj_add(j_event_test, "wakeup-events-total", (j_event = j_obj_new_obj()));
		j_obj_new_int64_add(j_event, "wakeup-total", total_delta);
		j_obj_new_double_add(j_event, "wakeup-rate-total", total_event_rate);
		j_obj_new_string_add(j_event, "load-hint-total", event_loading(total_event_rate));
	}
}

void event_init(void)
{
	/* Should really catch signals and set back to zero before we die */
        event_timer_stat_set("1", true);
}

void event_deinit(void)
{
        event_timer_stat_set("0", false);
}
