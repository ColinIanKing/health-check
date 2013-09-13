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
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <limits.h>
#include <grp.h>
#include <pwd.h>

#include "list.h"
#include "json.h"
#include "pid.h"
#include "proc.h"
#include "syscall.h"
#include "timeval.h"
#include "fnotify.h"
#include "event.h"
#include "cpustat.h"
#include "mem.h"
#include "net.h"
#include "ctxt-switch.h"
#include "health-check.h"

#define APP_NAME			"health-check"

volatile bool keep_running = true;
int opt_flags;
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
	event_stop();
	exit(status);
}

/*
 *  health_check_out_of_memory();
 *	report out of memory condition
 */
void health_check_out_of_memory(const char *msg)
{
	fprintf(stderr, "Out of memory: %s.\n", msg);
	health_check_exit(EXIT_FAILURE);
}

/*
 *  show_usage()
 *	show how to use
 */
static void show_usage(void)
{
	printf("%s, version %s\n\n", APP_NAME, VERSION);
	printf("Usage: %s [options] [command [options]]\n", APP_NAME);
	printf("Options are:\n");
	printf("  -b		brief (terse) output\n");
	printf("  -c            find all child and threads\n");
	printf("  -d            specify the analysis duration in seconds\n");
	printf("  -h            show this help\n");
	printf("  -p pid[,pid]  specify process id(s) or process name(s)\n");
	printf("  -m max        specify maximum number of system calls to trace\n");
#ifdef JSON_OUTPUT
	printf("  -o file       output results to a json data file\n");
#endif
	printf("  -r            resolve IP addresses\n");
	printf("  -u user       run command as a specified user\n");
	printf("  -v            verbose output\n");
	printf("  -w            monitor wakelock count\n");
	printf("  -W            monitor wakelock usage (has overhead)\n");

	health_check_exit(EXIT_SUCCESS);
}

/*
 *  parse_pid_list()
 *	parse list of process IDs or process names,
 *	collect process info in pids list
 */
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
			proc_pids_add_proc(pids, p);
		} else {
			if (proc_cache_find_by_procname(pids, token) < 0) {
				return -1;
			}
		}
	}

	return 0;
}

#ifdef JSON_OUTPUT
/*
 *  json_write()
 *	dump out collected JSON data
 */
static int json_write(json_object *obj, const char *filename)
{
	const char *str;
	FILE *fp;

	if (obj == NULL) {
		fprintf(stderr, "Cannot create JSON log, no JSON data\n");
		return -1;
	}

#ifdef JSON_C_TO_STRING_PRETTY
	str = json_object_to_json_string_ext(
		obj, JSON_C_TO_STRING_PRETTY);
#else
	str = json_object_to_json_string(obj);
#endif
	if (str == NULL) {
		fprintf(stderr, "Cannot turn JSON object to text for JSON output.\n");
		return -1;
	}
	if ((fp = fopen(filename, "w")) == NULL) {
		fprintf(stderr, "Cannot create JSON log file %s\n", filename);
		return -1;
	}

	fprintf(fp, "%s", str);
	fclose(fp);
	json_object_put(obj);

	return 0;
}
#endif

/*
 *  exec_executable()
 *	exec a program
 */
pid_t exec_executable(const char *opt_username, const char *path, char **argv)
{
	uid_t uid;
	gid_t gid;
	pid_t pid;
	struct stat buf;

	pid = fork();
	if (pid < 0) {
		fprintf(stderr, "Cannot fork to run %s\n", path);
		exit(EXIT_FAILURE);
	}
	if (pid != 0)
		return pid;	/* We are the tracer, return tracee pid */

	/* Traced process starts here */
	if (opt_username) {
		struct passwd *pw;
		uid_t euid;
		gid_t egid;

		if ((pw = getpwnam(opt_username)) == NULL) {
			fprintf(stderr, "Username %s does not exist\n", opt_username);
			exit(EXIT_FAILURE);
		}
		uid = pw->pw_uid;
		gid = pw->pw_gid;

		if (stat(path, &buf) != 0) {
			fprintf(stderr, "Cannot stat %s\n", path);
			health_check_exit(EXIT_FAILURE);
		}
		euid = buf.st_mode & S_ISUID ? buf.st_uid : uid;
		egid = buf.st_mode & S_ISGID ? buf.st_gid : gid;

		if (initgroups(opt_username, gid) < 0) {
			fprintf(stderr, "initgroups failed user on %s\n", opt_username);
			exit(EXIT_FAILURE);
		}
		if (setregid(gid, egid) < 0) {
			fprintf(stderr, "setregid failed\n");
			exit(EXIT_FAILURE);
		}
		if (setreuid(uid, euid) < 0) {
			fprintf(stderr, "setreuid failed\n");
			exit(EXIT_FAILURE);
		}
	} else {
		if (geteuid() != 0) {
			uid = getuid();
			if (setreuid(uid, uid) < 0) {
				fprintf(stderr, "setreuid failed\n");
				exit(EXIT_FAILURE);
			}
		}
	}

	/* Suspend ourself waiting for tracer */
	kill(getpid(), SIGSTOP);
	execv(path, argv);

	printf("Failed to execv %s\n", path);
	exit(EXIT_FAILURE);
}

/*
 *  is_executable()
 *	check path to see if it is an executable image
 */
inline static int is_executable(const char *path)
{
	struct stat buf;

	return ((stat(path, &buf) == 0) &&
	    (buf.st_mode & (S_IXUSR | S_IXGRP | S_IXOTH)) &&
	    S_ISREG(buf.st_mode));
}

/*
 *  find_executable()
 *	find executable given a filename
 */
static const char *find_executable(const char *filename)
{
	static char path[PATH_MAX];
	size_t filenamelen = strlen(filename);

	if (strchr(filename, '/')) {
		/* Given a full path, try this */
		if (strlen(filename) > sizeof(path) - 1) {
			fprintf(stderr, "executable name too long.\n");
			health_check_exit(EXIT_FAILURE);
		}
		strncpy(path, filename, sizeof(path) - 1);
		if (is_executable(path))
			return path;
		else 
			fprintf(stderr, "%s is not a valid executable program\n", filename);
	} else {
		/* Try and find it in $PATH */
		size_t skiplen;
		char *p;

		for (p = getenv("PATH"); p && *p; p += skiplen) {
			size_t len, pathlen;
			char *ptr = strchr(p, ':');

			if (ptr) {
				len = ptr - p;
				skiplen = len + 1;
			} else {
				skiplen = len = strlen(p);
			}

			if (len) {
				if (len > sizeof(path) - 1)
					continue;	/* Too long */
				else {
					pathlen = len;
					strncpy(path, p, pathlen);
				}
			} else {
				if (getcwd(p, PATH_MAX) == NULL)
					continue;	/* Silently ignore */
				pathlen = strlen(p);
			}
		
			if (pathlen + filenamelen + 2 > sizeof(path))
				continue;

			if ((pathlen > 0) && (path[pathlen - 1] != '/')) {
				if (pathlen >= sizeof(path) - 1)
					continue;	/* Too big! */
				path[pathlen++] = '/';
			}

			/* is Filename + '/' + pathname + EOS too big? */
			if (filenamelen + pathlen >= sizeof(path) - 2)
				continue;
			strcpy(path + pathlen, filename);

			if (is_executable(path))
				return path;
		}
		fprintf(stderr, "Cannot find %s in $PATH\n", filename);
	}
	return NULL;	/* No hope */
}

int main(int argc, char **argv)
{
	double actual_duration, opt_duration_secs = 60.0;
	struct timeval tv_start, tv_end, tv_now, duration;
	int ret, rc = EXIT_SUCCESS, fan_fd = 0;
	list_t pids;
	link_t *l;
	void *buffer;
	char *opt_username = NULL;
#ifdef JSON_OUTPUT
	char *opt_json_file = NULL;
	json_object *json_obj = NULL;
#endif
	json_object *json_tests = NULL;

	list_init(&pids);
	proc_cache_init();

	/* Get a cached view of current process state */
	proc_cache_get();
	proc_cache_get_pthreads();

	signal(SIGCHLD, SIG_DFL);

	for (;;) {
		int c = getopt(argc, argv, "+bcd:hp:m:o:ru:vwW");
		if (c == -1)
			break;
		switch (c) {
		case 'b':
			opt_flags |= OPT_BRIEF;
			break;
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
#ifdef JSON_OUTPUT
		case 'o':
			opt_json_file = optarg;
			break;
#endif
		case 'r':
			opt_flags |= OPT_ADDR_RESOLVE;
			break;
		case 'u':
			opt_username = optarg;
			break;
		case 'v':
			opt_flags |= OPT_VERBOSE;
			break;
		case 'w':
			opt_flags |= OPT_WAKELOCKS_LIGHT;
			break;
		case 'W':
			opt_flags |= OPT_WAKELOCKS_HEAVY;
			break;
		default:
			show_usage();
		}
	}

	if ((opt_flags & (OPT_VERBOSE | OPT_BRIEF)) == (OPT_VERBOSE | OPT_BRIEF)) {
		fprintf(stderr, "Cannot have verbose -v and brief -b flags together.\n");
		health_check_exit(EXIT_FAILURE);
	}

	if ((getuid() !=0 ) || (geteuid() != 0)) {
		fprintf(stderr, "%s requires root privileges to write to %s\n",
			APP_NAME, TIMER_STATS);
		health_check_exit(EXIT_FAILURE);
	}

	if (optind < argc) {
		const char *path;

		if (pids.head != NULL) {
			fprintf(stderr, "Cannot heath-check a program and provide pids to trace at same time\n");
			health_check_exit(EXIT_FAILURE);
		}

		argv += optind;
		path = find_executable(argv[0]);
		if (path) {
			pid_t pid = exec_executable(opt_username, path, argv);
			proc_info_t *p;
			if ((p = proc_cache_add(pid, 0, false)) == NULL) {
				fprintf(stderr, "Cannot find process with PID %i\n", pid);
				return -1;
			}
			free(p->cmdline);
			p->cmdline = strdup(basename(path));
			proc_pids_add_proc(&pids, p);
		} else
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

	net_connection_init();
	net_connection_pids(&pids);

#ifdef JSON_OUTPUT
	if (opt_json_file) {
		if ((json_obj = json_object_new_object()) == NULL)
			health_check_out_of_memory("cannot allocate JSON object");
		if ((json_tests = json_object_new_object()) == NULL)
			health_check_out_of_memory("cannot allocate JSON array");
		json_object_object_add(json_obj, "health-check", json_tests);
	}
#endif
	fnotify_init();
	if ((fan_fd = fnotify_event_init()) < 0)
		health_check_exit(EXIT_FAILURE);

	ret = posix_memalign(&buffer, 4096, 4096);
	if (ret != 0 || buffer == NULL)
		health_check_out_of_memory("cannot allocate 4K aligned buffer");

	signal(SIGINT, &handle_sigint);
	syscall_init();
	syscall_trace_proc(&pids);

	mem_init();
	event_init();
	cpustat_init();
	ctxt_switch_init();

	duration.tv_sec = (time_t)opt_duration_secs;
	duration.tv_usec = (suseconds_t)(opt_duration_secs * 1000000.0) - (duration.tv_sec * 1000000);

	gettimeofday(&tv_start, NULL);
	tv_end = timeval_add(&tv_start, &duration);

	event_get_all_pids(&pids, PROC_START);
	cpustat_get_all_pids(&pids, PROC_START);
	mem_get_all_pids(&pids, PROC_START);
	ctxt_switch_get_all_pids(&pids, PROC_START);

	gettimeofday(&tv_now, NULL);
	duration = timeval_sub(&tv_end, &tv_now);

	while ((procs_traced > 0) &&
	       keep_running &&
	       timeval_to_double(&duration) > 0.0) {
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
						fnotify_event_add(&pids, metadata);
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

	event_get_all_pids(&pids, PROC_FINISH);
	cpustat_get_all_pids(&pids, PROC_FINISH);
	mem_get_all_pids(&pids, PROC_FINISH);
	ctxt_switch_get_all_pids(&pids, PROC_FINISH);
	event_stop();

	signal(SIGINT, SIG_DFL);

	cpustat_dump_diff(json_tests, actual_duration);
	event_dump_diff(json_tests, actual_duration);
	ctxt_switch_dump_diff(json_tests, actual_duration);
	fnotify_dump_events(json_tests, actual_duration, &pids);
	syscall_dump_hashtable(json_tests, actual_duration);
	syscall_dump_pollers(json_tests, actual_duration);
	mem_dump_diff(json_tests, actual_duration);
	net_connection_dump(json_tests);

	if (opt_flags & OPT_WAKELOCKS_LIGHT)
		fnotify_dump_wakelocks(json_tests, actual_duration);

	if (opt_flags & OPT_WAKELOCKS_HEAVY)
		syscall_dump_wakelocks(json_tests, actual_duration, &pids);

	if (actual_duration < 5.0)
		printf("Analysis ran for just %.4f seconds, so rate calculations may be misleading\n",
			actual_duration);

#ifdef JSON_OUTPUT
	if (json_obj)
		json_write(json_obj, opt_json_file);
#endif

out:
	mem_cleanup();
	net_connection_cleanup();
	syscall_cleanup();
	event_cleanup();
	cpustat_cleanup();
	ctxt_switch_cleanup();
	fnotify_cleanup();
	free(buffer);
	proc_cache_cleanup();
	list_free(&pids, NULL);

	health_check_exit(rc);
}
