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
#include <ctype.h>
#include <dirent.h>

#define APP_NAME		"health-check"
#define TIMER_STATS		"/proc/timer_stats"

#define	OPT_GET_CHILDREN	0x00000001

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
typedef int  (*list_comp_t)(void *, void *);


typedef struct {
	long		padding;
	pid_t		pid;
	pid_t		ppid;
	char		*comm;
	char		*cmdline;
	bool		thread;
} proc_info_t;

typedef struct {
	proc_info_t	*proc;		/* Proc specific info */
	char		*func;		/* Kernel waiting func */
	char		*callback;	/* Kernel timer callback func */
	char		*ident;		/* Unique identity */
	unsigned long	count;		/* Number of events */
} event_info_t;

typedef struct {
	proc_info_t	*proc;		/* Proc specific info */
	unsigned long	utime;		/* User time quantum */
	unsigned long	stime;		/* System time quantum */
	unsigned long	ttime;		/* Total time */
} cpustat_info_t;

typedef struct {
	proc_info_t	*proc;		/* Proc specific info */
	char		*filename;	/* Name of device or filename being accessed */
	int		mask;		/* fnotify access mask */
	unsigned 	count;		/* Count of accesses */
} fnotify_fileinfo_t;

typedef struct {
	unsigned long 	open_total;
	unsigned long 	close_total;
	unsigned long 	read_total;
	unsigned long 	write_total;
	unsigned long 	total;
	proc_info_t   	*proc;
} io_ops_t;

static bool keep_running = true;
static int  opt_flags;

static list_t	proc_cache;

/*
 *  Stop gcc complaining about no return func
 */
static void health_check_exit(const int status) __attribute__ ((noreturn));


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
 *  list_add_ordered()
 *	add new data into list, based on order from callback func compare().
 */
static link_t *list_add_ordered(list_t *list, void *new_data, list_comp_t compare)
{
	link_t *link, **l;

	if ((link = calloc(1, sizeof(link_t))) == NULL)
		return NULL;

	link->data = new_data;

	for (l = &list->head; *l; l = &(*l)->next) {
		void *data = (void *)(*l)->data;
		if (compare(data, new_data) >= 0) {
			link->next = (*l);
			break;
		}
	}
	if (!link->next)
		list->tail = link;

	*l = link;
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

/*
 *  get_pid_comm
 *
 */
static char *get_pid_comm(const pid_t pid)
{
	char buffer[4096];
	int fd;
	ssize_t ret;

	snprintf(buffer, sizeof(buffer), "/proc/%i/comm", pid);

	if ((fd = open(buffer, O_RDONLY)) < 0)
		return NULL;

	if ((ret = read(fd, buffer, sizeof(buffer))) <= 0) {
		close(fd);
		return NULL;
	}
	close(fd);
	buffer[ret-1] = '\0';

	return strdup(buffer);
}

/*
 *  get_pid_cmdline
 * 	get process's /proc/pid/cmdline
 */
static char *get_pid_cmdline(const pid_t pid)
{
	char buffer[4096];
	char *ptr;
	int fd;
	ssize_t ret;

	snprintf(buffer, sizeof(buffer), "/proc/%i/cmdline", pid);

	if ((fd = open(buffer, O_RDONLY)) < 0)
		return NULL;

	if ((ret = read(fd, buffer, sizeof(buffer))) <= 0) {
		close(fd);
		return NULL;
	}
	close(fd);

	buffer[ret] = '\0';

	for (ptr = buffer; *ptr && (ptr < buffer + ret); ptr++) {
		if (*ptr == ' ')
			*ptr = '\0';
	}

	return strdup(basename(buffer));
}

/*
 *  pid_exists()
 *	true if given process with given pid exists
 */
static bool pid_exists(pid_t pid)
{
	char path[PATH_MAX];
	struct stat statbuf;

	snprintf(path, sizeof(path), "/proc/%i", pid);
	return stat(path, &statbuf) == 0;
}

static proc_info_t *find_proc_info_by_pid(pid_t pid);

static proc_info_t *add_proc_cache(pid_t pid, pid_t ppid, bool thread)
{
	proc_info_t *p;
	link_t *l;

	if (!pid_exists(pid))
		return NULL;


	for (l = proc_cache.head; l; l = l->next) {
		proc_info_t *p = (proc_info_t *)l->data;
		if (p->pid == pid)
			return p;
	}

	if ((p = calloc(1, sizeof(*p))) == NULL) {
		fprintf(stderr, "Out of memory\n");
		health_check_exit(EXIT_FAILURE);
	}

	p->pid  = pid;
	p->ppid = ppid;
	p->cmdline = get_pid_cmdline(pid);
	p->comm = get_pid_comm(pid);
	p->thread = thread;
	list_append(&proc_cache, p);

	return p;
}

static proc_info_t *find_proc_info_by_pid(pid_t pid)
{
	link_t *l;

	for (l = proc_cache.head; l; l = l->next) {
		proc_info_t *p = (proc_info_t *)l->data;

		if (p->pid == pid)
			return p;
	}

	return add_proc_cache(pid, 0, false);	/* Need to find parent really */
}

static int get_proc_cache(void)
{
	DIR *procdir;
	struct dirent *procentry;

	if ((procdir = opendir("/proc")) == NULL) {
		fprintf(stderr, "Cannot open directory /proc\n");
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
			if (fscanf(fp, "%d (%[^)]) %*c %i", &pid, comm, &ppid) == 3) {
				add_proc_cache(pid, ppid, false);
			}
			fclose(fp);
		}
	}
	closedir(procdir);

	return 0;
}

static int get_proc_cache_pthreads(void)
{
	DIR *procdir;
	struct dirent *procentry;

	if ((procdir = opendir("/proc")) == NULL) {
		fprintf(stderr, "Cannot open directory /proc\n");
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

		add_proc_cache(ppid, 0, false);

		while ((taskentry = readdir(taskdir)) != NULL) {
			pid_t pid;
			if (!isdigit(taskentry->d_name[0]))
				continue;
			pid = atoi(taskentry->d_name);
			if (pid == ppid)
				continue;

			add_proc_cache(pid, ppid, true);
		}
		closedir(taskdir);
	}
	closedir(procdir);

	return 0;
}

static void free_pid_info(void *data)
{
	proc_info_t *p = (proc_info_t*)data;

	free(p->cmdline);
	free(p->comm);
	free(p);
}

#if DUMP_PROC_CACHE
static void dump_proc_cache(void)
{
	link_t *l;

	for (l = proc_cache.head; l; l = l->next) {
		proc_info_t *p = (proc_info_t*)l->data;
		printf("%i %i %d (%s) (%s)\n",
			p->pid, p->ppid, p->thread, p->comm, p->cmdline);
	}
}
#endif

static int find_proc_info_by_procname(list_t *pids, const char *procname) {

	bool found = false;
	link_t *l;

	for (l = proc_cache.head; l; l = l->next) {
		proc_info_t *p = (proc_info_t *)l->data;

		if (p->cmdline && strcmp(p->cmdline, procname) == 0) {
			list_append(pids, p);
			found = true;
		}
	}

	if (!found) {
		fprintf(stderr, "Cannot find process %s\n", procname);
		return -1;
	}

	return 0;
}

static int pid_find(pid_t pid, list_t *list)
{
	link_t *l;

	for (l = list->head; l; l = l->next) {
		proc_info_t *p = (proc_info_t*)l->data;
		if (p->pid == pid)
			return true;
	}
	return false;
}

static int pid_get_children(pid_t pid, list_t *children)
{
	link_t *l;

	for (l = proc_cache.head; l; l = l->next) {
		proc_info_t *p = (proc_info_t*)l->data;
		if (p->ppid == pid) {
			list_append(children, p);
			pid_get_children(p->pid, children);
		}
	}

	return 0;
}

static int pids_get_children(list_t *pids)
{
	link_t *l;
	list_t children;
	proc_info_t *p;

	list_init(&children);

	for (l = pids->head; l; l = l->next) {
		p = (proc_info_t *)l->data;
		pid_get_children(p->pid, &children);
	}

	/*  Append the children onto the pid list */
	for (l = children.head; l; l = l->next) {
		p = (proc_info_t *)l->data;
		if (!pid_find(p->pid, pids))
			list_append(pids, p);
	}

	/*  Free the children list, not the data */
	list_free(&children, NULL);

	for (l = pids->head; l; l = l->next)
		p = (proc_info_t *)l->data;

	return 0;
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
 *  health_check_exit()
 *	exit and set timer stat to 0
 */
static void health_check_exit(const int status)
{
	set_timer_stat("0", false);

	exit(status);
}

static void handle_sigint(int dummy)
{
	(void)dummy;	/* Stop unused parameter warning with -Wextra */

	keep_running = false;
}

static void event_free(void *data)
{
	event_info_t *ev = (event_info_t *)data;

	free(ev->func);
	free(ev->callback);
	free(ev->ident);
	free(ev);
}

static int events_cmp(void *data1, void *data2)
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
	const unsigned long count,	/* event count */
	const pid_t pid,		/* PID of task */
	char *func,			/* Kernel function */
	char *callback)			/* Kernel timer callback */
{
	char ident[4096];
	event_info_t	*ev;
	link_t *l;
	proc_info_t	*p;

	/* Does it exist? */
	if ((p = find_proc_info_by_pid(pid)) == NULL)
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

	list_add_ordered(events, ev, events_cmp);
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

	printf("   PID  Process               Wake/Sec Kernel Functions\n");
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
		printf("  %5d %-20.20s %9.2f (%s, %s)\n",
			evn->proc->pid, evn->proc->cmdline,
			(double)delta / duration, 
			evn->func, evn->callback);
	}
	printf("\n");
}

static int cpustat_cmp(void *data1, void *data2)
{
	cpustat_info_t	*cpustat1 = (cpustat_info_t *)data1;
	cpustat_info_t	*cpustat2 = (cpustat_info_t *)data2;

	return cpustat2->ttime - cpustat1->ttime;
}

static void dump_cpustat_diff(double duration, list_t *cpustat_old, list_t *cpustat_new)
{
	double nr_ticks =
		/* (double)sysconf(_SC_NPROCESSORS_CONF) * */
		(double)sysconf(_SC_CLK_TCK) *
		duration;

	link_t *lo, *ln;
	list_t	sorted;
	cpustat_info_t *cio, *cin;

	list_init(&sorted);

	for (ln = cpustat_new->head; ln; ln = ln->next) {
		cin = (cpustat_info_t*)ln->data;

		for (lo = cpustat_old->head; lo; lo = lo->next) {
			cio = (cpustat_info_t*)lo->data;

			if (cin->proc->pid == cio->proc->pid) {
				cpustat_info_t *cpustat;

				if ((cpustat = calloc(1, sizeof(*cpustat))) == NULL) {
					fprintf(stderr, "Out of memory\n");
					health_check_exit(EXIT_FAILURE);
				}
				cpustat->proc  = cio->proc;
				cpustat->utime = cin->utime - cio->utime;
				cpustat->stime = cin->stime - cio->stime;
				cpustat->ttime = cin->ttime - cio->ttime;
				list_add_ordered(&sorted, cpustat, cpustat_cmp);
			}
		}
	}

	printf("CPU usage:\n");
	printf("   PID  Process                USR%%   SYS%%\n");
	for (ln = sorted.head; ln; ln = ln->next) {
		cin = (cpustat_info_t*)ln->data;
		printf("  %5d %-20.20s %6.2f %6.2f\n",
			cin->proc->pid,
			cin->proc->cmdline,
			100.0 * (double)cin->utime / (double)nr_ticks,
			100.0 * (double)cin->stime / (double)nr_ticks);
	}

	list_free(&sorted, free);

	printf("\n");
}

static void fnotify_event_free(void *data)
{
	fnotify_fileinfo_t *fileinfo = (fnotify_fileinfo_t *)data;

	free(fileinfo->filename);
	free(fileinfo);
}

static void fnotify_event_add(
	list_t *pids,
	const struct fanotify_event_metadata *metadata,
	list_t *fnotify_files)
{
	link_t *l;

	if ((metadata->fd == FAN_NOFD) && (metadata->fd < 0))
		return;

	for (l = pids->head; l; l = l->next) {
		 proc_info_t *p = (proc_info_t*)l->data;

		if (metadata->pid == p->pid) {
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
				fileinfo->proc = p;
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
					fnotify_event_free(fileinfo);
				} else {
					list_append(fnotify_files, fileinfo);
				}
			}
		}
	}
	close(metadata->fd);
}

static int fnotify_events_cmp_count(void *data1, void *data2)
{
	fnotify_fileinfo_t *info1 = (fnotify_fileinfo_t *)data1;
	fnotify_fileinfo_t *info2 = (fnotify_fileinfo_t *)data2;

	return info2->count - info1->count;
}

static int fnotify_events_cmp_io_ops(void *data1, void *data2)
{
	io_ops_t *io_ops1 = (io_ops_t *)data1;
	io_ops_t *io_ops2 = (io_ops_t *)data2;

	return io_ops2->total - io_ops1->total;
}

static void dump_fnotify_events(double duration, list_t *pids, list_t *fnotify_files)
{
	link_t 	*l;
	link_t  *lp;
	list_t	sorted;

	printf("File I/O Operations:\n");
	if (fnotify_files->head == NULL) {
		printf("  No file I/O operations detected\n\n");
		return;
	}

	list_init(&sorted);
	for (l = fnotify_files->head; l; l = l->next) {
		fnotify_fileinfo_t *info = (fnotify_fileinfo_t *)l->data;
		list_add_ordered(&sorted, info, fnotify_events_cmp_count);
		
	}

	printf("   PID  Process               Count  Op  Filename\n");
	for (l = sorted.head; l; l = l->next) {
		fnotify_fileinfo_t *info = (fnotify_fileinfo_t *)l->data;
		char modes[5];
		int i = 0;

		if (info->mask & FAN_OPEN)
			modes[i++] = 'O';
		if (info->mask & (FAN_CLOSE_WRITE | FAN_CLOSE_NOWRITE))
			modes[i++] = 'C';
		if (info->mask & FAN_ACCESS)
			modes[i++] = 'R';
		if (info->mask & (FAN_MODIFY | FAN_CLOSE_WRITE))
			modes[i++] = 'W';
		modes[i] = '\0';

		printf("  %5d %-20.20s %6d %4s %s\n",
			info->proc->pid, info->proc->comm,
			info->count, modes, info->filename);
	}
	printf("\n");
	list_free(&sorted, NULL);

	list_init(&sorted);
	for (lp = pids->head; lp; lp = lp->next) {
		proc_info_t *p = (proc_info_t*)lp->data;
		io_ops_t *io_ops;

		if ((io_ops = calloc(1, sizeof(*io_ops))) == NULL) {
			fprintf(stderr, "Out of memory\n");
			health_check_exit(EXIT_FAILURE);
		}
		io_ops->proc = p;

		for (l = fnotify_files->head; l; l = l->next) {
			fnotify_fileinfo_t *info = (fnotify_fileinfo_t *)l->data;

			if (info->proc->pid != p->pid)
				continue;

			if (info->mask & FAN_OPEN)
				io_ops->open_total += info->count;
			if (info->mask & (FAN_CLOSE_WRITE | FAN_CLOSE_NOWRITE))
				io_ops->close_total += info->count;
			if (info->mask & FAN_ACCESS)
				io_ops->read_total += info->count;
			if (info->mask & (FAN_MODIFY | FAN_CLOSE_WRITE))
				io_ops->write_total += info->count;
		}
		io_ops->total = io_ops->open_total + io_ops->close_total + 
				io_ops->read_total + io_ops->write_total;

		if (io_ops->total)
			list_add_ordered(&sorted, io_ops, fnotify_events_cmp_io_ops);
	}

	printf("File I/O Operations per second:\n");
	printf("   PID  Process                 Open   Close    Read   Write\n");
	for (l = sorted.head; l; l = l->next) {
		io_ops_t *io_ops = (io_ops_t *)l->data;

		printf("  %5d %-20.20s %7.2f %7.2f %7.2f %7.2f\n",
			io_ops->proc->pid, io_ops->proc->cmdline,
			(double)io_ops->open_total / duration,
			(double)io_ops->close_total / duration,
			(double)io_ops->read_total / duration,
			(double)io_ops->write_total / duration);
	}
	printf("\n");
	list_free(&sorted, free);
}

/*
 *  get_cpustat()
 *
 */
static int get_cpustat(list_t *pids, list_t *cpustat)
{
	char filename[PATH_MAX];
	FILE *fp;
	link_t *l;

	for (l = pids->head; l; l = l->next) {
		proc_info_t *p = (proc_info_t *)l->data;

		if (p->thread)
			continue;

		snprintf(filename, sizeof(filename), "/proc/%d/stat", p->pid);
		if ((fp = fopen(filename, "r")) != NULL) {
			char comm[20];
			unsigned long utime, stime;
			pid_t pid;

			/* 3173 (a.out) R 3093 3173 3093 34818 3173 4202496 165 0 0 0 3194 0 */
			if (fscanf(fp, "%d (%[^)]) %*c %*d %*d %*d %*d %*d %*u %*u %*u %*u %*u %lu %lu",
				&pid, comm, &utime, &stime) == 4) {
				cpustat_info_t *info;

				info = calloc(1, sizeof(*info));
				if (info == NULL) {
					fprintf(stderr, "Out of memory\n");
					health_check_exit(EXIT_FAILURE);
				}
				info->proc  = p;
				info->utime = utime;
				info->stime = stime;
				info->ttime = utime + stime;
				list_append(cpustat, info);
			}
			fclose(fp);
		}
	}

	return 0;
}


/*
 *  get_events()
 *	scan /proc/timer_stats and populate a timer stat hash table with
 *	unique events
 */
static void get_events(list_t *pids, list_t *events)
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
		char comm[64];
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
		sscanf(buf, "%lu", &count);
		sscanf(ptr, "%d %s %s (%[^)])", &event_pid, comm, func, timer);

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
		if ((ret < 0) && (errno != ENOENT)) {
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
	printf("Usage: %s [options]\n", APP_NAME);
	printf("Options are:\n");
	printf("  -c            find all child and threads\n");
	printf("  -d            specify the analysis duration in seconds\n");
	printf("  -h            show this help\n");
	printf("  -p pid[,pid]  specify process id(s) or process name(s) \n");
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
			if ((p = find_proc_info_by_pid(pid)) == NULL) {
				fprintf(stderr, "Cannot find process with PID %i\n", pid);
				return -1;
			}
			list_append(pids, p);
		} else {
			if (find_proc_info_by_procname(pids, token) < 0) {
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
	int ret;
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

	get_proc_cache();
	get_proc_cache_pthreads();
#if DUMP_PROC_CACHE
	dump_proc_cache();
#endif

	for (;;) {
		int c = getopt(argc, argv, "cd:hp:");
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
		pids_get_children(&pids);


	if (opt_duration_secs < 0.5) {
		fprintf(stderr, "Duration must 0.5 or more.\n");
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

	get_events(&pids, &event_info_old);
	get_cpustat(&pids, &cpustat_info_old);

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

	duration = timeval_sub(&tv_now, &tv_start);
	actual_duration = timeval_to_double(&duration);

	get_events(&pids, &event_info_new);
	get_cpustat(&pids, &cpustat_info_new);

	dump_cpustat_diff(actual_duration, &cpustat_info_old, &cpustat_info_new);
	dump_events_diff(actual_duration, &event_info_old, &event_info_new);
	dump_fnotify_events(actual_duration, &pids, &fnotify_files);

out:
	free(buffer);
	list_free(&pids, NULL);
	list_free(&event_info_old, event_free);
	list_free(&event_info_new, event_free);
	list_free(&cpustat_info_old, free);
	list_free(&cpustat_info_new, free);
	list_free(&fnotify_files, fnotify_event_free);
	list_free(&proc_cache, free_pid_info);

	health_check_exit(EXIT_SUCCESS);
}
