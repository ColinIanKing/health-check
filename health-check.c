/*
 * Copyright (C) 2011-2013 Canonical
 * Hugely modified parts from powertop-1.13, Copyright 2007, Intel Corporation
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

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <limits.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <math.h>
#include <mntent.h>
#include <sys/fanotify.h>

#define APP_NAME		"health-check"
#define TIMER_STATS		"/proc/timer_stats"

typedef struct link {
	void *data;			/* Data in list */
	struct link *next;		/* Next item in list */
} link_t;

typedef struct {
	link_t	*head;			/* Head of list */
	link_t	*tail;			/* Tail of list */
	size_t	length;			/* Length of list */
} list_t;

typedef void (*list_link_free_t)(void *);

typedef struct {
	pid_t		pid;
	char 		*task;		/* Name of process/kernel task */
	char		*cmdline;	/* From /proc/$pid/cmdline */
	char		*func;		/* Kernel waiting func */
	char		*callback;	/* Kernel timer callback func */
	char		*ident;		/* Unique identity */
	unsigned long	count;		/* Number of events */
} event_info_t;

typedef struct {
	pid_t		pid;		/* Process ID */
	unsigned long	utime;		/* User time quantum */
	unsigned long	stime;		/* System time quantum */
	bool		valid;		/* Valid info */
} cpustat_info_t;

typedef struct {
	pid_t		pid;		/* Process ID */
	char		*filename;	/* Name of device or filename being accessed */
	int		mask;		/* fnotify access mask */
	unsigned 	count;		/* Count of accesses */
} fnotify_fileinfo_t;

static pid_t opt_pid;			/* PID of process to check */
static bool keep_running = true;

/*
 *  pid_exists()
 *	true if given process with given pid exists
 */
bool pid_exists(pid_t pid)
{
	char path[PATH_MAX];
	struct stat statbuf;

	snprintf(path, sizeof(path), "/proc/%i", pid);
	return stat(path, &statbuf) == 0;
}

/*
 *  timeval_to_double()
 *	convert timeval to seconds as a double
 */
static double timeval_to_double(const struct timeval *tv)
{
	return (double)tv->tv_sec + ((double)tv->tv_usec / 1000000.0);
}


/*
 *  timeval_add()
 *	timeval a + b
 */
static struct timeval timeval_add(const struct timeval *a, const struct timeval *b)
{
	struct timeval ret;

	ret.tv_sec = a->tv_sec + b->tv_sec;
	ret.tv_usec = a->tv_usec + b->tv_usec;
	if (ret.tv_usec > 1000000) {
		int nsec = (ret.tv_usec / 1000000);
		ret.tv_sec += nsec;
		ret.tv_usec -= (1000000 * nsec);
	}

	return ret;
}

/*
 *  timeval_sub()
 *	timeval a - b
 */
static struct timeval timeval_sub(const struct timeval *a, const struct timeval *b)
{
	struct timeval ret, _b;

	_b.tv_sec = b->tv_sec;
	_b.tv_usec = b->tv_usec;

	if (a->tv_usec < _b.tv_usec) {
		int nsec = ((_b.tv_usec - a->tv_usec) / 1000000) + 1;
		_b.tv_sec += nsec;
		_b.tv_usec -= (1000000 * nsec);
	}
	if (a->tv_usec - _b.tv_usec > 1000000) {
		int nsec = (a->tv_usec - _b.tv_usec) / 1000000;
		_b.tv_sec -= nsec;
		_b.tv_usec += (1000000 * nsec);
	}

	ret.tv_sec = a->tv_sec - _b.tv_sec;
	ret.tv_usec = a->tv_usec - _b.tv_usec;

	return ret;
}


/*
 *  timeval_double
 *	timeval to a double
 */
static inline double timeval_double(const struct timeval *tv)
{
	return (double)tv->tv_sec + ((double)tv->tv_usec / 1000000.0);
}

/*
 *  set_timer_stat()
 *	enable/disable timer stat
 */
static void set_timer_stat(const char *str, const bool carp)
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
 *  Stop gcc complaining about no return func
 */
static void health_check_exit(const int status) __attribute__ ((noreturn));

/*
 *  health_check_exit()
 *	exit and set timer stat to 0
 */
static void health_check_exit(const int status)
{
	set_timer_stat("0", false);

	exit(status);
}

/*
 *  list_init()
 *	initialize list
 */
static inline void list_init(list_t *list)
{
	list->head = NULL;
	list->tail = NULL;
	list->length = 0;
}

/*
 *  list_append()
 *	add a new item to end of the list
 */
static link_t *list_append(list_t *list, void *data)
{
	link_t *link;

	if ((link = calloc(1, sizeof(link_t))) == NULL) {
		fprintf(stderr, "Cannot allocate list link\n");
		health_check_exit(EXIT_FAILURE);
	}
	link->data = data;

	if (list->head == NULL) {
		list->head = link;
	} else {
		list->tail->next = link;
	}
	list->tail = link;
	list->length++;

	return link;
}

/*
 *  list_free()
 *	free the list
 */
static void list_free(list_t *list, const list_link_free_t freefunc)
{
	link_t	*link, *next;

	if (list == NULL)
		return;

	for (link = list->head; link; link = next) {
		next = link->next;
		if (link->data && freefunc)
			freefunc(link->data);
		free(link);
	}
}

static void handle_sigint(int dummy)
{
	(void)dummy;	/* Stop unused parameter warning with -Wextra */

	keep_running = false;
}

/*
 *  get_pid_cmdline
 * 	get process's /proc/pid/cmdline
 */
static char *get_pid_cmdline(const pid_t id)
{
	char buffer[4096];
	char *ptr;
	int fd;
	ssize_t ret;

	snprintf(buffer, sizeof(buffer), "/proc/%d/cmdline", id);

	if ((fd = open(buffer, O_RDONLY)) < 0)
		return NULL;

	if ((ret = read(fd, buffer, sizeof(buffer))) <= 0) {
		close(fd);
		return NULL;
	}

	close(fd);

	buffer[sizeof(buffer)-1] = '\0';

	for (ptr = buffer; *ptr && (ptr < buffer + ret); ptr++) {
		if (*ptr == ' ')
			*ptr = '\0';
	}

	return strdup(basename(buffer));
}

/*
 *  event_add()
 *	add timer stats to a hash table if it is new, otherwise just
 *	accumulate the event count.
 */
static void event_add(
	list_t *events,			/* event list */
	const unsigned long count,	/* event count */
	const pid_t pid,		/* PID of task */
	char *task,			/* Name of task */
	char *func,			/* Kernel function */
	char *callback)			/* Kernel timer callback */
{
	char ident[4096];
	event_info_t	*ev;
	link_t *l;

	snprintf(ident, sizeof(ident), "%d:%s:%s:%s", pid, task, func, callback);

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

	ev->pid = pid;
	ev->task = strdup(task);
	ev->cmdline = get_pid_cmdline(pid);
	ev->func = strdup(func);
	ev->callback = strdup(callback);
	ev->ident = strdup(ident);
	ev->count = count;

	if (ev->task == NULL ||
	    ev->func == NULL ||
	    ev->callback == NULL ||
	    ev->ident == NULL) {
		fprintf(stderr, "Out of memory\n");
		health_check_exit(EXIT_FAILURE);
	}

	list_append(events, ev);
}

static void dump_events_diff(double duration, list_t *events_old, list_t *events_new)
{
	link_t *ln, *lo;
	event_info_t *evo, *evn;

	printf("Wakeups:\n");
	if (events_new->head == NULL) {
		printf("  No wakeups detected\n\n");
		return;
	}

	printf("  Rate   Function                       Callback\n");
	for (ln = events_new->head; ln; ln = ln->next) {
		evn = (event_info_t*)ln->data;
		unsigned long delta = evn->count;

		for (lo = events_old->head; lo; lo = lo->next) {
			evo = (event_info_t*)lo->data;
			if (strcmp(evn->ident, evo->ident) == 0) {
				delta = evn->count - evo->count;
				break;
			}
		}
		printf("  %6.2f %-30.30s %-30.30s\n", (double)delta / duration, evn->func, evn->callback);
	}
	printf("\n");
}

static void dump_cpustat_diff(double duration, cpustat_info_t *cpustat_old, cpustat_info_t *cpustat_new)
{
	double nr_ticks =
		(double)sysconf(_SC_NPROCESSORS_CONF) *
		(double)sysconf(_SC_CLK_TCK) *
		duration;

	if (cpustat_old->valid && cpustat_new->valid) {
		unsigned long utime = cpustat_new->utime - cpustat_old->utime;
		unsigned long stime = cpustat_new->stime - cpustat_old->stime;

		printf("CPU usage (in terms of %lu CPUs):\n",
			sysconf(_SC_NPROCESSORS_CONF));
		printf("  User:   %6.2f%%\n",
			100.0 * (double)utime / (double)nr_ticks);
		printf("  System: %6.2f%%\n",
			100.0 * (double)stime / (double)nr_ticks);
		printf("\n");
	}
}

static void fnotify_event_add(const pid_t pid, const struct fanotify_event_metadata *metadata, list_t *fnotify_files)
{
	if ((metadata->fd == FAN_NOFD) && (metadata->fd < 0))
		return;

	if (metadata->pid == pid) {
		char buf[256];
		char path[PATH_MAX];
		ssize_t len;
		fnotify_fileinfo_t *fileinfo;


		if ((fileinfo = calloc(1, sizeof(*fileinfo))) != NULL) {
			link_t	*l;
			bool	found = false;

			snprintf(buf, sizeof(buf), "/proc/self/fd/%d", metadata->fd);
			len = readlink(buf, path, sizeof(path));
			if (len < 0) {
				struct stat statbuf;
				if (fstat(metadata->fd, &statbuf) < 0)
					fileinfo->filename = NULL;
				else {
					snprintf(buf, sizeof(buf), "dev: %i:%i inode %ld",
						major(statbuf.st_dev), minor(statbuf.st_dev), statbuf.st_ino);
					fileinfo->filename = strdup(buf);
				}
			} else {
				path[len] = '\0';
				fileinfo->filename = strdup(path);
			}
			fileinfo->mask = metadata->mask;
			fileinfo->pid = metadata->pid;
			fileinfo->count = 1;

			for (l = fnotify_files->head; l; l = l->next) {
				fnotify_fileinfo_t *fi = (fnotify_fileinfo_t *)l->data;

				if ((fileinfo->mask == fi->mask) &&
				    (strcmp(fileinfo->filename, fi->filename) == 0)) {
					found = true;
					fi->count++;
					break;
				}
			}

			if (found) {
				free(fileinfo->filename);
				free(fileinfo);
			} else {
				list_append(fnotify_files, fileinfo);
			}
		}
	}
	close(metadata->fd);
}

static void dump_fnotify_events(double duration, list_t *fnotify_files)
{
	link_t 	*l;
	unsigned long open_total = 0;
	unsigned long close_total = 0;
	unsigned long read_total = 0;
	unsigned long write_total = 0;

	printf("File I/O operations:\n");
	if (fnotify_files->head == NULL) {
		printf("  No file I/O operations detected\n\n");
		return;
	}
	printf("   Count  Op  Filename\n");

	for (l = fnotify_files->head; l; l = l->next) {
		fnotify_fileinfo_t *info = (fnotify_fileinfo_t *)l->data;
		char modes[5];
		int i = 0;

		if (info->mask & FAN_OPEN) {
			open_total += info->count;
			modes[i++] = 'O';
		}
		if (info->mask & (FAN_CLOSE_WRITE | FAN_CLOSE_NOWRITE)) {
			close_total += info->count;
			modes[i++] = 'C';
		}
		if (info->mask & FAN_ACCESS) {
			read_total += info->count;
			modes[i++] = 'R';
		}
		if (info->mask & (FAN_MODIFY | FAN_CLOSE_WRITE)) {
			write_total += info->count;
			modes[i++] = 'W';
		}
		modes[i] = '\0';
		printf("  %6d %4s %s\n", info->count, modes, info->filename);
	}
	printf("\n");
	printf("  Rate   Operation\n");
	printf("  %6.2f Open\n",  (double)open_total / duration);
	printf("  %6.2f Close\n", (double)close_total / duration);
	printf("  %6.2f Read\n",  (double)read_total / duration);
	printf("  %6.2f Write\n", (double)write_total / duration);
	printf("\n");
}

/*
 *  get_cpustats()
 *
 */
static void get_cpustat(pid_t pid, cpustat_info_t *cpustat)
{
	char filename[PATH_MAX];
	char comm[20];
	FILE *fp;

	cpustat->valid = false;

	snprintf(filename, sizeof(filename), "/proc/%d/stat", pid);
	/* 3173 (a.out) R 3093 3173 3093 34818 3173 4202496 165 0 0 0 3194 0 */
	if ((fp = fopen(filename, "r")) != NULL) {
		if (fscanf(fp, "%d (%[^)]) %*c %*d %*d %*d %*d %*d %*u %*u %*u %*u %*u %lu %lu",
			&pid, comm, &cpustat->utime, &cpustat->stime) == 4)
			cpustat->valid = true;
		fclose(fp);
	}
}


/*
 *  get_events()
 *	scan /proc/timer_stats and populate a timer stat hash table with
 *	unique events
 */
static void get_events(pid_t pid, list_t *events)
{
	FILE *fp;
	char buf[4096];

	if ((fp = fopen(TIMER_STATS, "r")) == NULL) {
		fprintf(stderr, "Cannot open %s\n", TIMER_STATS);
		return;
	}

	while (!feof(fp)) {
		char *ptr = buf;
		unsigned long count = -1;
		pid_t event_pid = -1;
		char task[64];
		char func[128];
		char timer[128];

		if (fgets(buf, sizeof(buf), fp) == NULL)
			break;

		if (strstr(buf, "total events") != NULL)
			break;

		if (strstr(buf, ",") == NULL)
			continue;

		/* format: count[D], pid, task, func (timer) */

		while (*ptr && *ptr != ',')
			ptr++;

		if (*ptr != ',')
			continue;

		if (ptr > buf && *(ptr-1) == 'D')
			continue;	/* Deferred event, skip */

		ptr++;
		sscanf(buf, "%lu", &count);
		sscanf(ptr, "%d %s %s (%[^)])", &event_pid, task, func, timer);

		if (event_pid == pid)

		event_add(events, count, pid, task, func, timer);
	}

	fclose(fp);
}

static int fnotify_init(void)
{
	int fan_fd;
	int ret;
	FILE* mounts;
	struct mntent* mount;

	if ((fan_fd = fanotify_init (0, 0)) < 0) {
		fprintf(stderr, "Cannot initialize fanotify: %s\n", strerror(errno));
		return -1;
	}

	ret = fanotify_mark(fan_fd, FAN_MARK_ADD | FAN_MARK_MOUNT,
		FAN_ACCESS| FAN_MODIFY | FAN_OPEN | FAN_CLOSE |  FAN_ONDIR | FAN_EVENT_ON_CHILD,
		AT_FDCWD, "/");
	if (ret < 0) {
		fprintf(stderr, "Cannot add fanotify watch on /: %s\n", strerror(errno));
		return -1;
	}

	if ((mounts = setmntent("/proc/self/mounts", "r")) == NULL) {
		fprintf(stderr, "Cannot get mount points\n");
		return -1;
	}

	while ((mount = getmntent (mounts)) != NULL) {
		if (access (mount->mnt_fsname, F_OK) != 0)
			continue;

		ret = fanotify_mark(fan_fd, FAN_MARK_ADD | FAN_MARK_MOUNT,
			FAN_ACCESS| FAN_MODIFY | FAN_OPEN | FAN_CLOSE | FAN_ONDIR | FAN_EVENT_ON_CHILD,
			AT_FDCWD, mount->mnt_dir);
		if (ret < 0) {
			fprintf(stderr, "Cannot add watch on %s mount %s: %s\n",
				mount->mnt_type, mount->mnt_dir, strerror (errno));
		}
	}

	endmntent (mounts);

	return fan_fd;
}

/*
 *  show_usage()
 *	show how to use
 */
static void show_usage(void)
{
	printf("%s, version %s\n\n", APP_NAME, VERSION);
	printf("Usage: %s [options] [duration] [count]\n", APP_NAME);
	printf("Options are:\n");
	printf("  -h\tshow this help\n");
	printf("  -p pid\tspecify process id of process to check\n");
}

int main(int argc, char **argv)
{
	double opt_duration_secs = 1.0;
	struct timeval tv_start, tv_end, tv_now, duration;
	double actual_duration;
	int ret;
	list_t		event_info_old, event_info_new;
	list_t		fnotify_files;
	cpustat_info_t	cpustat_info_old, cpustat_info_new;
	int fan_fd;
	void *buffer;

	list_init(&event_info_old);
	list_init(&event_info_new);
	list_init(&fnotify_files);

	for (;;) {
		int c = getopt(argc, argv, "d:hp:");
		if (c == -1)
			break;
		switch (c) {
		case 'h':
			show_usage();
			break;
		case 'p':
			opt_pid = atoi(optarg);
			break;
		case 'd':
			opt_duration_secs = atof(optarg);
			break;
		}
	}

	if (!pid_exists(opt_pid)) {
		fprintf(stderr, "Cannot check process %i, no such process pid\n", opt_pid);
		health_check_exit(EXIT_FAILURE);
	}

	if (opt_duration_secs < 0.5) {
		fprintf(stderr, "Duration must 0.5 or more.\n");
		health_check_exit(EXIT_FAILURE);
	}

	if (geteuid() != 0) {
		fprintf(stderr, "%s requires root privileges to write to %s\n",
			APP_NAME, TIMER_STATS);
		health_check_exit(EXIT_FAILURE);
	}

	if ((fan_fd = fnotify_init()) < 0) {
		health_check_exit(EXIT_FAILURE);
	}

	ret = posix_memalign(&buffer, 4096, 4096);
	if (ret != 0 || buffer == NULL) {
		fprintf(stderr, "Cannot allocate 4K aligned buffer\n");
		health_check_exit(EXIT_FAILURE);
	}

	signal(SIGINT, &handle_sigint);

	/* Should really catch signals and set back to zero before we die */
	set_timer_stat("1", true);

	duration.tv_sec = (time_t)opt_duration_secs;
	duration.tv_usec = (suseconds_t)(opt_duration_secs * 1000000.0) - (duration.tv_sec * 1000000);

	gettimeofday(&tv_start, NULL);
	tv_end = timeval_add(&tv_start, &duration);

	get_events(opt_pid, &event_info_old);
	get_cpustat(opt_pid, &cpustat_info_old);

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
						fnotify_event_add(opt_pid, metadata, &fnotify_files);
						metadata = FAN_EVENT_NEXT(metadata, len);
					}
				}
			}
		}
		gettimeofday(&tv_now, NULL);
		duration = timeval_sub(&tv_end, &tv_now);
	}

	duration = timeval_sub(&tv_now, &tv_start);
	actual_duration = timeval_to_double(&duration);

	get_events(opt_pid, &event_info_new);
	get_cpustat(opt_pid, &cpustat_info_new);

	dump_events_diff(actual_duration, &event_info_old, &event_info_new);
	dump_cpustat_diff(actual_duration, &cpustat_info_old, &cpustat_info_new);
	dump_fnotify_events(actual_duration, &fnotify_files);

out:
	list_free(&event_info_old, free);
	list_free(&event_info_new, free);
	list_free(&fnotify_files, free);

	health_check_exit(EXIT_SUCCESS);
}
