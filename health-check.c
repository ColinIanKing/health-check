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

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <pthread.h>
#include <ctype.h>
#include <math.h>
#include <errno.h>
#include <sys/fanotify.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
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

#define DURATION_RUN_FOREVER		(0.0)

static bool caught_sigint = false;
volatile bool keep_running = true;
int opt_flags;
long int opt_max_syscalls = 1000000;

/*
 *  pid_max_digits()
 *	determine (or guess) maximum digits of pids
 */
int pid_max_digits(void)
{
	static int max_digits;
	ssize_t n;
	int fd;
	const int default_digits = 6;
	const int min_digits = 5;
	char buf[32];

	if (max_digits)
		goto ret;

	max_digits = default_digits;
	fd = open("/proc/sys/kernel/pid_max", O_RDONLY);
	if (fd < 0)
		goto ret;
	n = read(fd, buf, sizeof(buf) - 1);
	(void)close(fd);
	if (n < 0)
		goto ret;

	buf[n] = '\0';
	max_digits = 0;
	while (buf[max_digits] >= '0' && buf[max_digits] <= '9')
		max_digits++;
	if (max_digits < min_digits)
		max_digits = min_digits;
ret:
	return max_digits;
}

/*
 *  handle_sig()
 *	catch signal, stop program
 */
static void handle_sig(int dummy)
{
	(void)dummy;    /* Stop unused parameter warning with -Wextra */

	keep_running = false;
	caught_sigint = true;
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
	printf("  -c            find all child processes on start-up\n");
	printf("                (only useful with -p option)\n");
	printf("  -d            specify the analysis duration in seconds\n");
	printf("                (default is 60 seconds)\n");
	printf("  -f		follow fork/vfork/clone system calls\n");
	printf("  -h            show this help\n");
	printf("  -p pid[,pid]  specify process id(s) or process name(s) to be traced\n");
	printf("  -m max        specify maximum number of system calls to trace\n");
	printf("		(default is 1000000)\n");
#ifdef JSON_OUTPUT
	printf("  -o file       output results to a json data file\n");
#endif
	printf("  -r            resolve IP addresses\n");
	printf("  -u user       run command as a specified user\n");
	printf("  -v            verbose output\n");
#if FNOTIFY_SUPPORTED
	printf("  -w            monitor wakelock count\n");
#endif
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
	char *str, *token;

	for (str = arg; (token = strtok(str, ",")) != NULL; str = NULL) {
		if (isdigit(token[0])) {
			proc_info_t *p;
			pid_t pid;

			errno = 0;
			pid = strtol(token, NULL, 10);
			if (errno) {
				fprintf(stderr, "Invalid pid specified.\n");
				return -1;
			}
			if ((p = proc_cache_find_by_pid(pid)) == NULL) {
				fprintf(stderr, "Cannot find process with PID %i.\n", pid);
				return -1;
			}
			if (proc_pids_add_proc(pids, p) < 0)
				return -1;
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
		fprintf(stderr, "Cannot create JSON log, no JSON data.\n");
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
		fprintf(stderr, "Cannot create JSON log file %s.\n", filename);
		return -1;
	}

	fprintf(fp, "%s", str);
	(void)fclose(fp);
	json_object_put(obj);

	return 0;
}
#endif

/*
 *  exec_executable()
 *	exec a program
 */
static pid_t exec_executable(const char *opt_username, const char *path, char **argv)
{
	uid_t uid;
	gid_t gid;
	pid_t pid;

	pid = fork();
	if (pid < 0) {
		fprintf(stderr, "Cannot fork to run %s.\n", path);
		exit(EXIT_FAILURE);
	}
	if (pid != 0)
		return pid;	/* We are the tracer, return tracee pid */

	/* Traced process starts here */
	if (opt_username) {
		struct passwd *pw;

		if ((pw = getpwnam(opt_username)) == NULL) {
			fprintf(stderr, "Username %s does not exist.\n", opt_username);
			exit(EXIT_FAILURE);
		}
		uid = pw->pw_uid;
		gid = pw->pw_gid;

		if (initgroups(opt_username, gid) < 0) {
			fprintf(stderr, "initgroups failed user on %s\n", opt_username);
			exit(EXIT_FAILURE);
		}
		if (setregid(gid, gid) < 0) {
			fprintf(stderr, "setregid failed\n");
			exit(EXIT_FAILURE);
		}
		if (setreuid(uid, uid) < 0) {
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
	int ret, rc = EXIT_SUCCESS;
#if FNOTIFY_SUPPORTED
	int fan_fd = 0;
#endif
	list_t pids;
	link_t *l;
	void *buffer = NULL;
	char *opt_username = NULL;
#ifdef JSON_OUTPUT
	char *opt_json_file = NULL;
	json_object *json_obj = NULL;
#endif
	json_object *json_tests = NULL;
	struct sigaction new_action, old_action;

	list_init(&pids);
	proc_cache_init();

	/* Get a cached view of current process state */
	if (proc_cache_get() < 0)
		goto out;
	if (proc_cache_get_pthreads() < 0)
		goto out;

	sigaction(SIGCHLD, NULL, &old_action);
	if (old_action.sa_handler != SIG_DFL) {
		new_action.sa_handler = SIG_DFL;
		sigemptyset(&new_action.sa_mask);
		new_action.sa_flags = 0;
		sigaction(SIGCHLD, &new_action, NULL);
	}

	for (;;) {
		int c = getopt(argc, argv, "+bcd:fhp:m:o:ru:vwW");
		if (c == -1)
			break;
		switch (c) {
		case 'b':
			opt_flags |= OPT_BRIEF;
			break;
		case 'c':
			opt_flags |= OPT_GET_CHILDREN;
			break;
		case 'f':
			opt_flags |= OPT_FOLLOW_NEW_PROCS;
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
			opt_flags |= OPT_DURATION;
			break;
		case 'm':
			errno = 0;
			opt_max_syscalls = strtol(optarg, NULL, 10);
			if (errno) {
				fprintf(stderr, "Invalid maximum number of system calls specified.\n");
				health_check_exit(EXIT_FAILURE);
			}
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
#if FNOTIFY_SUPPORTED
		case 'w':
			opt_flags |= OPT_WAKELOCKS_LIGHT;
			break;
#endif
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
			pid_t pid;
			proc_info_t *p;

			/* No duration given, so run until completion */
			if (!(opt_flags & OPT_DURATION))
				opt_duration_secs = DURATION_RUN_FOREVER;

			pid = exec_executable(opt_username, path, argv);
			if ((p = proc_cache_add(pid, 0, false)) == NULL) {
				fprintf(stderr, "Cannot find process with PID %i\n", pid);
				goto out;
			}
			free(p->cmdline);
			if ((p->cmdline = strdup(basename(path))) == NULL) {
				health_check_out_of_memory("cannot allocate process cmdline");
				goto out;
			}
			if (proc_pids_add_proc(&pids, p) < 0)
				goto out;
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
		if (pid_list_get_children(&pids) < 0)
			goto out;

	if (opt_duration_secs < 0.0) {
		fprintf(stderr, "Duration must positive.\n");
		health_check_exit(EXIT_FAILURE);
	}

	net_connection_init();
	if (net_connection_pids(&pids) < 0)
		goto out;

#ifdef JSON_OUTPUT
	if (opt_json_file) {
		if ((json_obj = json_object_new_object()) == NULL) {
			health_check_out_of_memory("cannot allocate JSON object");
			goto out;
		}
		if ((json_tests = json_object_new_object()) == NULL) {
			health_check_out_of_memory("cannot allocate JSON array");
			goto out;
		}
		json_object_object_add(json_obj, "health-check", json_tests);
	}
#endif
#if FNOTIFY_SUPPORTED
	fnotify_init();
	if ((fan_fd = fnotify_event_init()) < 0)
		goto out;
#endif

	ret = posix_memalign(&buffer, 4096, 4096);
	if (ret != 0 || buffer == NULL) {
		health_check_out_of_memory("cannot allocate 4K aligned buffer");
		goto out;
	}

	new_action.sa_handler = handle_sig;
	sigemptyset(&new_action.sa_mask);
	new_action.sa_flags = 0;
	sigaction(SIGINT, &new_action, &old_action);
	sigaction(SIGUSR1, &new_action, &old_action);
#if SYSCALL_SUPPORTED
	syscall_init();
	syscall_trace_proc(&pids);
#endif
	mem_init();
#if EVENT_SUPPORTED
	event_init();
#endif
	cpustat_init();
	ctxt_switch_init();

	duration.tv_sec = (time_t)opt_duration_secs;
	duration.tv_usec = (suseconds_t)(opt_duration_secs * 1000000.0) - (duration.tv_sec * 1000000);

	gettimeofday(&tv_start, NULL);
	tv_end = timeval_add(&tv_start, &duration);

#if EVENT_SUPPORTED
	if (event_get_all_pids(&pids, PROC_START) < 0)
		goto out;
#endif
	if (cpustat_get_all_pids(&pids, PROC_START) < 0)
		goto out;
	if (mem_get_all_pids(&pids, PROC_START) < 0)
		goto out;
	if (ctxt_switch_get_all_pids(&pids, PROC_START) < 0)
		goto out;

	gettimeofday(&tv_now, NULL);
	duration = timeval_sub(&tv_end, &tv_now);

	while ((procs_traced > 0) &&
	       keep_running &&
	       (FLOAT_CMP(opt_duration_secs, DURATION_RUN_FOREVER)||
		timeval_to_double(&duration) > 0.0)) {

		struct timeval *duration_ptr =
			FLOAT_CMP(opt_duration_secs, DURATION_RUN_FOREVER) ? NULL : &duration;
#if FNOTIFY_SUPPORTED
		fd_set rfds;
		FD_ZERO(&rfds);
		FD_SET(fan_fd, &rfds);

		ret = select(fan_fd + 1, &rfds, NULL, NULL, duration_ptr);
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
						if (fnotify_event_add(&pids, metadata) < 0)
							goto out;
						metadata = FAN_EVENT_NEXT(metadata, len);
					}
				}
			}
		}
#else
		ret = select(0, NULL, NULL, NULL, duration_ptr);
		if (ret < 0) {
			if (errno != EINTR) {
				fprintf(stderr, "Select failed: %s\n", strerror(errno));
				gettimeofday(&tv_now, NULL);
				goto out;
			}
		}
#endif
		gettimeofday(&tv_now, NULL);
		duration = timeval_sub(&tv_end, &tv_now);
	}
	keep_running = false;

	duration = timeval_sub(&tv_now, &tv_start);
	actual_duration = timeval_to_double(&duration);

#if EVENT_SUPPORTED
	if (event_get_all_pids(&pids, PROC_FINISH) < 0)
		goto out;
#endif
	if (cpustat_get_all_pids(&pids, PROC_FINISH) < 0)
		goto out;
	if (mem_get_all_pids(&pids, PROC_FINISH) < 0)
		goto out;
	if (ctxt_switch_get_all_pids(&pids, PROC_FINISH) < 0)
		goto out;
#if EVENT_SUPPORTED
	event_stop();
#endif
#if SYSCALL_SUPPORTED
	if (syscall_stop() < 0)
		goto out;
#endif

	sigaction(SIGINT, &old_action, NULL);

	if (caught_sigint)
		putchar('\n');

	cpustat_dump_diff(json_tests, actual_duration);
	pagefault_dump_diff(json_tests, actual_duration);
#if EVENT_SUPPORTED
	event_dump_diff(json_tests, actual_duration);
#endif
	ctxt_switch_dump_diff(json_tests, actual_duration);
#if FNOTIFY_SUPPORTED
	fnotify_dump_events(json_tests, actual_duration, &pids);
#endif
#if SYSCALL_SUPPORTED
	syscall_dump_hashtable(json_tests, actual_duration);
	syscall_dump_pollers(json_tests, actual_duration);
	syscall_dump_sync(json_tests, actual_duration);
	syscall_dump_inotify(json_tests, actual_duration);
	syscall_dump_execve(json_tests, actual_duration);
#endif
	if (mem_dump_diff(json_tests, actual_duration) < 0)
		goto out;
	mem_dump_brk(json_tests, actual_duration);
	mem_dump_mmap(json_tests, actual_duration);
	net_connection_dump(json_tests, actual_duration);

#if FNOTIFY_SUPPORTED
	if (opt_flags & OPT_WAKELOCKS_LIGHT)
		fnotify_dump_wakelocks(json_tests, actual_duration);
#endif

#if SYSCALL_SUPPORTED
	if (opt_flags & OPT_WAKELOCKS_HEAVY)
		syscall_dump_wakelocks(json_tests, actual_duration, &pids);
#endif

	if (actual_duration < 5.0)
		printf("Analysis ran for just %.4f seconds, so rate calculations may be misleading\n",
			actual_duration);

#ifdef JSON_OUTPUT
	if (json_obj)
		json_write(json_obj, opt_json_file);
#endif

out:
	keep_running = false;	/* Force stop if we aborted */
	mem_cleanup();
	net_connection_cleanup();
#if SYSCALL_SUPPORTED
	syscall_cleanup();
#endif
#if EVENT_SUPPORTED
	event_cleanup();
#endif
	cpustat_cleanup();
	ctxt_switch_cleanup();
#if FNOTIFY_SUPPORTED
	fnotify_cleanup();
#endif
	free(buffer);
	proc_cache_cleanup();
	list_free(&pids, NULL);

	health_check_exit(rc);
}
