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
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <pthread.h>
#include <ctype.h>
#include <errno.h>
#include <sys/fanotify.h>

#include "list.h"
#include "pid.h"
#include "proc.h"
#include "syscall.h"
#include "timeval.h"
#include "fnotify.h"
#include "event.h"
#include "cpustat.h"
#include "health-check.h"

#define APP_NAME			"health-check"

#define	OPT_GET_CHILDREN		0x00000001

volatile bool keep_running = true;
static int  opt_flags;
int opt_max_syscalls = 1000000;

/*
 *  handle_sigint()
 *	catch sigint, stop program
 */
static void handle_sigint(int dummy)
{
	(void)dummy;    /* Stop unused parameter warning with -Wextra */

	keep_running = false;
}

/*
 *  health_check_exit()
 *	exit and set timer stat to 0
 */
void health_check_exit(const int status)
{
	event_deinit();
	exit(status);
}

/*
 *  show_usage()
 *	show how to use
 */
static void show_usage(void)
{
	printf("%s, version %s\n\n", APP_NAME, VERSION);
	printf("Usage: %s [options]\n", APP_NAME);
	printf("Options are:\n");
	printf("  -c            find all child and threads\n");
	printf("  -d            specify the analysis duration in seconds\n");
	printf("  -h            show this help\n");
	printf("  -p pid[,pid]  specify process id(s) or process name(s)\n");
	printf("  -m max	specify maximum number of system calls to trace\n");
	health_check_exit(EXIT_SUCCESS);
}

static int parse_pid_list(char *arg, list_t *pids)
{
	char *str, *token, *saveptr = NULL;

	for (str = arg; (token = strtok_r(str, ",", &saveptr)) != NULL; str = NULL) {
		if (isdigit(token[0])) {
			proc_info_t *p;
			pid_t pid;

			pid = atoi(token);
			if ((p = proc_cache_find_by_pid(pid)) == NULL) {
				fprintf(stderr, "Cannot find process with PID %i\n", pid);
				return -1;
			}
			list_append(pids, p);
		} else {
			if (proc_cache_find_by_procname(pids, token) < 0) {
				return -1;
			}
		}
	}

	return 0;
}

int main(int argc, char **argv)
{
	double opt_duration_secs = 10.0;
	struct timeval tv_start, tv_end, tv_now, duration;
	double actual_duration;
	int ret, rc = EXIT_SUCCESS;
	list_t		event_info_old, event_info_new;
	list_t		fnotify_files, pids;
	list_t		cpustat_info_old, cpustat_info_new;
	link_t		*l;
	int fan_fd = 0;
	void *buffer;

	list_init(&event_info_old);
	list_init(&event_info_new);
	list_init(&cpustat_info_old);
	list_init(&cpustat_info_new);
	list_init(&fnotify_files);
	list_init(&pids);
	list_init(&proc_cache);

	proc_cache_get();
	proc_cache_get_pthreads();
#if DUMP_PROC_CACHE
	proc_cache_dump();
#endif

	for (;;) {
		int c = getopt(argc, argv, "cd:hp:m:");
		if (c == -1)
			break;
		switch (c) {
		case 'c':
			opt_flags |= OPT_GET_CHILDREN;
			break;
		case 'h':
			show_usage();
			break;
		case 'p':
			if (parse_pid_list(optarg, &pids) < 0)
				health_check_exit(EXIT_FAILURE);
			break;
		case 'd':
			opt_duration_secs = atof(optarg);
			break;
		case 'm':
			opt_max_syscalls = atoi(optarg);
			break;
		}
	}

	if (geteuid() != 0) {
		fprintf(stderr, "%s requires root privileges to write to %s\n",
			APP_NAME, TIMER_STATS);
		health_check_exit(EXIT_FAILURE);
	}

	if (pids.head == NULL) {
		fprintf(stderr, "Must provide one or more valid process IDs or name\n");
		health_check_exit(EXIT_FAILURE);
	}
	for (l = pids.head; l; l = l->next) {
		proc_info_t *p = (proc_info_t *)l->data;
		if (!pid_exists(p->pid)) {
			fprintf(stderr, "Cannot check process %i, no such process pid\n", p->pid);
			health_check_exit(EXIT_FAILURE);
		}
	}
	if (opt_flags & OPT_GET_CHILDREN)
		pid_list_get_children(&pids);

	if (opt_duration_secs < 0.5) {
		fprintf(stderr, "Duration must 0.5 or more.\n");
		health_check_exit(EXIT_FAILURE);
	}

	if ((fan_fd = fnotify_event_init()) < 0) {
		health_check_exit(EXIT_FAILURE);
	}

	ret = posix_memalign(&buffer, 4096, 4096);
	if (ret != 0 || buffer == NULL) {
		fprintf(stderr, "Cannot allocate 4K aligned buffer\n");
		health_check_exit(EXIT_FAILURE);
	}

	signal(SIGINT, &handle_sigint);
	for (l = pids.head; l; l = l->next) {
		proc_info_t *p = (proc_info_t *)l->data;
		if (!p->is_thread) {
			if (pthread_create(&p->pthread, NULL, syscall_trace, &p->pid) < 0) {
				fprintf(stderr, "Failed to create tracing thread for pid %i\n", p->pid);
				goto out;
			}
		}
	}

	event_init();

	duration.tv_sec = (time_t)opt_duration_secs;
	duration.tv_usec = (suseconds_t)(opt_duration_secs * 1000000.0) - (duration.tv_sec * 1000000);

	gettimeofday(&tv_start, NULL);
	tv_end = timeval_add(&tv_start, &duration);

	event_get(&pids, &event_info_old);
	cpustat_get(&pids, &cpustat_info_old);

	gettimeofday(&tv_now, NULL);
	duration = timeval_sub(&tv_end, &tv_now);

	while (keep_running && timeval_to_double(&duration) > 0.0) {
		fd_set rfds;
		FD_ZERO(&rfds);
		FD_SET(fan_fd, &rfds);

		ret = select(fan_fd + 1, &rfds, NULL, NULL, &duration);
		if (ret < 0) {
			if (errno != EINTR) {
				fprintf(stderr, "Select failed: %s\n", strerror(errno));
				gettimeofday(&tv_now, NULL);
				goto out;
			}
		} else if (ret > 0) {
			if (FD_ISSET(fan_fd, &rfds)) {
				ssize_t len;

				if ((len = read(fan_fd, (void *)buffer, 4096)) > 0) {
					const struct fanotify_event_metadata *metadata;
					metadata = (struct fanotify_event_metadata *)buffer;

					while (FAN_EVENT_OK(metadata, len)) {
						fnotify_event_add(&pids, metadata, &fnotify_files);
						metadata = FAN_EVENT_NEXT(metadata, len);
					}
				}
			}
		}
		gettimeofday(&tv_now, NULL);
		duration = timeval_sub(&tv_end, &tv_now);
	}
	keep_running = false;

	duration = timeval_sub(&tv_now, &tv_start);
	actual_duration = timeval_to_double(&duration);

	event_get(&pids, &event_info_new);
	cpustat_get(&pids, &cpustat_info_new);
	event_deinit();

	cpustat_dump_diff(actual_duration, &cpustat_info_old, &cpustat_info_new);
	event_dump_diff(actual_duration, &event_info_old, &event_info_new);
	fnotify_dump_events(actual_duration, &pids, &fnotify_files);
	syscall_dump_hashtable(actual_duration);
	syscall_dump_pollers(actual_duration);

out:
	for (l = pids.head; l; l = l->next) {
		proc_info_t *p = (proc_info_t *)l->data;
		if (!p->is_thread && p->pthread) {
			pthread_cancel(p->pthread);
			pthread_join(p->pthread, NULL);
		}
	}

	free(buffer);
	list_free(&pids, NULL);
	list_free(&event_info_old, event_free);
	list_free(&event_info_new, event_free);
	list_free(&cpustat_info_old, free);
	list_free(&cpustat_info_new, free);
	list_free(&fnotify_files, fnotify_event_free);
	list_free(&proc_cache, proc_cache_info_free);

	health_check_exit(rc);
}
