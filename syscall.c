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
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#if defined(__x86_64__) || defined(__i386__)
#include <sys/reg.h>
#endif
#include <sys/user.h>
#include <errno.h>
#include <linux/ptrace.h>
#include <limits.h>

#include "syscall.h"
#include "proc.h"
#include "json.h"
#include "net.h"
#include "mem.h"
#include "cpustat.h"
#include "fnotify.h"
#include "ctxt-switch.h"
#include "health-check.h"

#define HASH_TABLE_SIZE	(1997)		/* Must be prime */
#define ARRAY_SIZE(a)	(sizeof(a) / sizeof(a[0]))

static pthread_t syscall_tracer;
int procs_traced = 0;
static int syscall_count = 0;
static int info_emit = false;

static list_t syscall_wakelocks;
static list_t syscall_contexts;
static list_t *__pids;	/* We need to fix this into a global pids cache/list */

/* minimum allowed thresholds for poll'd system calls that have timeouts */
static double syscall_timeout[] = {
#ifdef SYS_clock_nanosleep
	TIMEOUT(clock_nanosleep, 1.0),
#endif
#ifdef SYS_epoll_pwait
	TIMEOUT(epoll_pwait, 1.0),
#endif
#ifdef SYS_epoll_wait
	TIMEOUT(epoll_wait, 1.0),
#endif
#ifdef SYS_mq_timedreceive
	TIMEOUT(mq_timedreceive, 1.0),
#endif
#ifdef SYS_mq_timedsend
	TIMEOUT(mq_timedsend, 1.0),
#endif
#ifdef SYS_nanosleep
	TIMEOUT(nanosleep, 1.0),
#endif
#ifdef SYS_poll
	TIMEOUT(poll, 1.0),
#endif
#ifdef SYS_ppoll
	TIMEOUT(ppoll, 1.0),
#endif
#ifdef SYS_pselect6
	TIMEOUT(pselect6, 1.0),
#endif
#ifdef SYS_recvmmsg
	TIMEOUT(recvmmsg, 1.0),
#endif
#ifdef SYS_rt_sigtimedwait
	TIMEOUT(rt_sigtimedwait, 1.0),
#endif
#ifdef SYS_select
	TIMEOUT(select, 1.0),
#endif
#ifdef SYS_semtimedop
	TIMEOUT(semtimedop, 1.0),
#endif
};


/* hash table for syscalls, hashed on pid and syscall number */
static syscall_info_t *syscall_info[HASH_TABLE_SIZE];

/* hash table for cached fds, hashed on pid and fd */
static fd_cache_t *fd_cache[HASH_TABLE_SIZE];

/*
 *  syscall_valid()
 *	is syscall in the syscall table bounds?
 */
static bool syscall_valid(const int syscall)
{
	return (syscall >= 0) &&
	       (syscall <= (int)syscalls_len);
}

#ifdef SYS_connect
/*
 *  syscall_connect()
 *	stub for connect syscalls.
 *	A smart approach is to inspect the connect and
 *	see what address is being connected to for the net_*
 *	connections.
 */
static void syscall_connect(
	const syscall_t *sc,
	syscall_info_t *s,
	const pid_t pid,
	const double threshold,
	double *ret_timeout)
{
	(void)sc;
	(void)s;
	(void)pid;
	(void)threshold;
	(void)ret_timeout;

	/* Inspect connect address, update network stats */
}

/*
 *  syscall_connect_ret()
 *	trigger a network connection update once a
 *	connect syscall has occurred.
 */
static void syscall_connect_ret(json_object *j_obj, const syscall_t *sc, const syscall_info_t *s)
{
	(void)j_obj;
	(void)sc;

	net_connection_pid(s->proc->pid);
}
#endif

/*
 *  syscall_nanosleep_generic_ret()
 *	handle nanosecond syscall returns
 */
#if defined(SYS_clock_nanosleep) || defined(SYS_nanosleep)
static void syscall_nanosleep_generic_ret(json_object *j_obj, const syscall_t *sc, const syscall_info_t *s)
{
	link_t *l;
#ifndef JSON_OUTPUT
	(void)j_obj;
#endif

	uint64_t ret_error = 0;

	for (l = s->return_history.head; l; l = l->next) {
		syscall_return_info_t *ret = (syscall_return_info_t *)l->data;
		if (ret->ret != 0)
			ret_error++;
	}

	if (ret_error) {
		printf(" %s (%i), %s:\n",
			s->proc->cmdline, s->proc->pid, sc->name);
		printf("   %8" PRIu64 " %s system call errors\n", ret_error, sc->name);
		info_emit = true;

#ifdef JSON_OUTPUT
		if (j_obj) {
			json_object *j_nanosleep_error, *j_error;

			j_obj_array_add(j_obj, (j_nanosleep_error= j_obj_new_obj()));
			j_obj_obj_add(j_nanosleep_error, "nanosleep-error", (j_error = j_obj_new_obj()));
			j_obj_new_int32_add(j_error, "pid", s->proc->pid);
			j_obj_new_int32_add(j_error, "ppid", s->proc->ppid);
			j_obj_new_int32_add(j_error, "is-thread", s->proc->is_thread);
			j_obj_new_string_add(j_error, "name", s->proc->cmdline);
			j_obj_new_string_add(j_error, "system-call", sc->name);
			j_obj_new_int64_add(j_error, "error-count", ret_error);
		}
#endif
	}
}
#endif

#if defined(SYS_epoll_pwait) || defined(SYS_epoll_wait) || \
    defined(SYS_poll) || defined(SYS_ppol) || \
    defined(SYS_pselect6) || defined(SYS_rt_sigtimedwait) || \
    defined(SYS_select)
/*
 *  syscall_poll_generic_ret()
 *	handle generic poll returns
 */
static void syscall_poll_generic_ret(json_object *j_obj, const syscall_t *sc, const syscall_info_t *s)
{
	link_t *l;
	int prev_ret = -1;
	double prev_timeout = -1.0;
	uint64_t zero_timeout_repeats = 0;
	uint64_t zero_timeouts = 0;
	uint64_t timeout_repeats = 0;
	uint64_t ret_error = 0;
#ifndef JSON_OUTPUT
	(void)j_obj;
#endif

	for (l = s->return_history.head; l; l = l->next) {
		syscall_return_info_t *ret = (syscall_return_info_t *)l->data;

		/* Timed out? */
		if (ret->ret == 0) {
			/* And the timeout time was zero, we're abusing the poll */
			if (ret->timeout == 0.0) {
				zero_timeouts++;
				/* And if the previous poll was also abusive.. */
				if (prev_ret == 0) {
					if (prev_timeout == 0.0) {
						/* somebody is polling hard and wasting cycles */
						zero_timeout_repeats++;
					} else {
						/* polling, but not so hard */
						timeout_repeats++;
					}
				}
			}
		} else if (ret->ret < 0)
			ret_error++;

		prev_ret = ret->ret;
		prev_timeout = ret->timeout;
	}

	if (zero_timeouts | timeout_repeats | zero_timeout_repeats | ret_error) {
		printf(" %s (%i), %s:\n",
			s->proc->cmdline, s->proc->pid, sc->name);
		if (zero_timeouts)
			printf("   %8" PRIu64 " immediate timed out calls with zero timeout (non-blocking peeks)\n", zero_timeouts);
		if (timeout_repeats)
			printf("   %8" PRIu64 " repeated timed out polled calls with non-zero timeouts (light polling)\n", timeout_repeats);
		if (zero_timeout_repeats)
			printf("   %8" PRIu64 " repeated immediate timed out polled calls with zero timeouts (heavy polling peeks)\n", zero_timeout_repeats);
		if (ret_error)
			printf("   %8" PRIu64 " system call errors\n", ret_error);
		info_emit = true;
	}

#ifdef JSON_OUTPUT
	if (j_obj) {
		json_object *j_timeout, *j_poll;

		j_obj_array_add(j_obj, (j_timeout = j_obj_new_obj()));
		j_obj_obj_add(j_timeout, "polling-timeout", (j_poll = j_obj_new_obj()));

		j_obj_new_int32_add(j_poll, "pid", s->proc->pid);
		j_obj_new_int32_add(j_poll, "ppid", s->proc->ppid);
		j_obj_new_int32_add(j_poll, "is-thread", s->proc->is_thread);
		j_obj_new_string_add(j_poll, "name", s->proc->cmdline);
		j_obj_new_string_add(j_poll, "system-call", sc->name);
		j_obj_new_int64_add(j_poll, "zero-timeouts", zero_timeouts);
		j_obj_new_int64_add(j_poll, "repeat-timeouts", timeout_repeats);
		j_obj_new_int64_add(j_poll, "repeat-zero-timeouts", zero_timeout_repeats);
		j_obj_new_int64_add(j_poll, "error-count", ret_error);
	}
#endif
}
#endif

#if defined(SYS_semtimedop)
static void syscall_semtimedop_ret(json_object *j_obj, const syscall_t *sc, const syscall_info_t *s)
{
	(void)j_obj,
	(void)sc;
	(void)s;
	/* No-op for now, need to examine errno */
}
#endif

#if defined(SYS_mq_timedreceive)
static void syscall_mq_timedreceive_ret(json_object *j_obj, const syscall_t *sc, const syscall_info_t *s)
{
	(void)j_obj,
	(void)sc;
	(void)s;
	/* No-op for now, need to examine errno */
}
#endif

#if defined(SYS_mq_timedsend)
static void syscall_mq_timedsend_ret(json_object *j_obj, const syscall_t *sc, const syscall_info_t *s)
{
	(void)j_obj,
	(void)sc;
	(void)s;
	/* No-op for now, need to examine errno */
}
#endif

/*
 *  syscall_is_call_entry()
 *	are we entering a system call (true) or exiting it (false)
 */
static bool syscall_is_call_entry(const pid_t pid)
{
#if defined(__x86_64__)
	errno = 0;
	if (ptrace(PTRACE_PEEKUSER, pid, 8 * RAX, NULL) != -ENOSYS)
		return false;
	if (errno) {
		return false;
	}
	return true;

#elif defined(__i386__)
	errno = 0;
	if (ptrace(PTRACE_PEEKUSER, pid, 8 * EAX, NULL) != -ENOSYS)
		return false;
	if (errno)
		return false;
	return true;

#elif defined(__arm__)
	(void)pid;

	return true;	/* Need to fix this */
#endif
	return false;
}


/*
 *  syscall_get_call()
 *	get syscall number
 */
static int syscall_get_call(const pid_t pid, int *syscall)
{
#if defined(__x86_64__)
	errno = 0;
	*syscall = ptrace(PTRACE_PEEKUSER, pid, 8 * ORIG_RAX, NULL);
	if (errno) {
		*syscall = -1;
		return -1;
	}
	return 0;
#elif defined(__i386__)
	errno = 0;
	*syscall = ptrace(PTRACE_PEEKUSER, pid, 4 * ORIG_EAX, NULL);
	if (errno) {
		*syscall = -1;
		return -1;
	}
	return 0;
#elif defined(__arm__)
	struct pt_regs regs;
	unsigned long sc;

	errno = 0;
	ptrace(PTRACE_GETREGS, pid, NULL, (void *)&regs);
	if (errno) {
		*syscall = -1;
		return -1;
	}

	/* Thumb mode */
	if (regs.ARM_cpsr & 0x20) {
		*syscall = regs.ARM_r7;
		return 0;
	}

	errno = 0;
	sc = ptrace(PTRACE_PEEKTEXT, pid, (void *)(regs.ARM_pc - 4), NULL);
	if (errno) {
		*syscall = -1;
		return -1;
	}

	if (sc == 0xef000000)
		sc = regs.ARM_r7;
	else {
		if ((sc & 0x0ff00000) != 0x0f900000) {
			fprintf(stderr, "bad syscall trap 0x%lx\n", sc);
			*syscall = -1;
			return -1;
		}
		sc &= 0xfffff;
	}

	if (sc & 0x0f0000)
		sc &= 0xffff;

	*syscall = sc;
	return 0;
#else
#error Only currently implemented for x86 and ARM
	*syscall = -1;
	return -1
#endif
}

/*
 *  syscall_get_return()
 *	get syscall return code
 */
static int syscall_get_return(const pid_t pid, int *rc)
{
#if defined (__x86_64__)
	errno = 0;
	*rc = ptrace(PTRACE_PEEKUSER, pid, sizeof(long) * RAX, NULL);
	if (errno)
		return -1;
	if (*rc == -ENOSYS) {
		printf("got unexpected SYSCALL entry\n");
		return -1;	/* Not in syscall entry */
	}
	return 0;
#elif defined (__i386__)
	errno = 0;
	*rc = ptrace(PTRACE_PEEKUSER, pid, sizeof(long) * EAX, NULL);
	if (errno)
		return -1;
	if (*rc == -ENOSYS) {
		printf("got unexpected SYSCALL entry\n");
		return -1;	/* Not in syscall entry */
	}
	return 0;
#elif defined (__arm__)
	struct pt_regs regs;

	errno = 0;
	ptrace(PTRACE_GETREGS, pid, NULL, (void *)&regs);
	if (errno)
		return -1;

	*rc = regs.ARM_r0;
	return 0;
#else
	fprintf(stderr, "Unknown arch\n");
	return -1;
#endif
}

/*
 *  syscall_get_args()
 *	fetch n args from system call
 */
static int syscall_get_args(
	const pid_t pid,
	const int arg,
	unsigned long args[])
{
#if defined (__i386__)
	int i;

	for (i = 0; i <= arg; i++)
		args[i] = ptrace(PTRACE_PEEKUSER, pid, i * 4, &args);
	return 0;
#elif defined (__x86_64__)
	int i;
	long cs;
	int *regs;
	static int regs32[] = { RBX, RCX, RDX, RSI, RDI, RBP };
	static int regs64[] = { RDI, RSI, RDX, R10, R8,  R9 };

	cs = ptrace(PTRACE_PEEKUSER, pid, 8*CS, NULL);
	switch (cs) {
	case 0x23:	/* 32 bit mode */
		regs = regs32;
		break;
	case 0x33:	/* 64 bit mode */
		regs = regs64;
		break;
	default:
		fprintf(stderr, "Unknown personality, CS=0x%x\n", (int)cs);
		return -1;
	}

	for (i = 0; i <= arg; i++)
		args[i] = ptrace(PTRACE_PEEKUSER, pid, regs[i] * 8, NULL);
	return 0;
#elif defined (__arm__)
	int i;
	struct pt_regs regs;

	if (ptrace(PTRACE_GETREGS, pid, NULL, (void *)&regs) < 0)
		return -1;

	for (i = 0; i <= arg; i++)
		args[i] = regs.uregs[i];

	return 0;
#else
	int i;

	for (i = 0; i <= arg; i++)
		args[i] = 0;

	fprintf(stderr, "Unknown arch\n");
	return -1;
#endif
}

/*
 *  syscall_name
 *	get system call name
 */
static void syscall_name(const int syscall, char *name, const size_t len)
{
	if (syscall_valid(syscall) && (syscalls[syscall].name)) {
		strncpy(name, syscalls[syscall].name, len);
	} else {
		/*  Don't know it */
		snprintf(name, len, "SYS_NR_%d", syscall);
	}
}

/*
 *  hash_syscall()
 *	hash syscall and pid
 */
static inline unsigned long hash_syscall(const pid_t pid, const int syscall)
{
	unsigned long h;

	h = (pid ^ (pid << 3) ^ syscall) % HASH_TABLE_SIZE;
	return h;
}

/*
 *  hash_fd()
 *	hash fd and pid
 */
static inline unsigned long hash_fd(const pid_t pid, const int fd)
{
	unsigned long h;

	h = (pid ^ (pid << 3) ^ fd) % HASH_TABLE_SIZE;
	return h;
}

/*
 *  syscall_count_cmp()
 *	syscall usage count sort comparitor
 */
static int syscall_count_cmp(const void *data1, const void *data2)
{
	syscall_info_t *s1 = (syscall_info_t *)data1;
	syscall_info_t *s2 = (syscall_info_t *)data2;

	return s2->count - s1->count;
}

/*
 *  syscall_hashtable_free()
 *	free syscall hash table
 */
static void syscall_hashtable_free(void)
{
	int i;

	for (i = 0; i < HASH_TABLE_SIZE; i++) {
		syscall_info_t *next, *s = syscall_info[i];

		while (s) {
			next = s->next;
			free(s);
			s = next;
		}
	}
}

/*
 *  syscall_dump_hashtable
 *	dump syscall hashtable stats
 */
void syscall_dump_hashtable(json_object *j_tests, const double duration)
{
	list_t sorted;
	link_t *l;
	int i;
	int count = 0;
	uint64_t total;
#ifndef JSON_OUTPUT
	(void)j_tests;
#endif

	if (opt_flags & OPT_BRIEF)
		return;

	list_init(&sorted);

	for (i = 0; i < HASH_TABLE_SIZE; i++) {
		syscall_info_t *s;

		for (s = syscall_info[i]; s; s = s->next)
			list_add_ordered(&sorted, s, syscall_count_cmp);
	}

	printf("System calls traced:\n");
	printf("  PID  Process              Syscall               Count    Rate/Sec\n");
	for (total = 0, l = sorted.head; l; l = l->next) {
		char name[64];
		syscall_info_t *s = (syscall_info_t *)l->data;

		syscall_name(s->syscall, name, sizeof(name));
		printf(" %5i %-20.20s %-20.20s %6" PRIu64 " %12.4f\n",
			s->proc->pid, s->proc->cmdline, name, s->count, (double)s->count / duration);
		count++;
		total += s->count;
	}
	if (count > 1) {
		printf(" %-46.46s%8" PRIu64 " %12.4f\n", "Total",
			total, (double)total / duration);
	}
	printf("\n");

#ifdef JSON_OUTPUT
	if (j_tests) {
		json_object *j_syscall, *j_syscall_infos, *j_syscall_info;

		j_obj_obj_add(j_tests, "system-calls", (j_syscall = j_obj_new_obj()));
                j_obj_obj_add(j_syscall, "system-calls-per-process", (j_syscall_infos = j_obj_new_array()));
		for (total = 0, l = sorted.head; l; l = l->next) {
			char name[64];
			syscall_info_t *s = (syscall_info_t *)l->data;

			syscall_name(s->syscall, name, sizeof(name));
			j_syscall_info = j_obj_new_obj();
			j_obj_new_int32_add(j_syscall_info, "pid", s->proc->pid);
			j_obj_new_int32_add(j_syscall_info, "ppid", s->proc->ppid);
			j_obj_new_int32_add(j_syscall_info, "is-thread", s->proc->is_thread);
			j_obj_new_string_add(j_syscall_info, "name", s->proc->cmdline);
			j_obj_new_string_add(j_syscall_info, "system-call", name);
			j_obj_new_int64_add(j_syscall_info, "system-call-count", s->count);
			j_obj_new_double_add(j_syscall_info, "system-call-rate",
				(double)s->count / duration);
			j_obj_array_add(j_syscall_infos, j_syscall_info);
			total += s->count;
		}
		j_obj_obj_add(j_syscall, "system-calls-total", (j_syscall_info = j_obj_new_obj()));
		j_obj_new_int64_add(j_syscall_info, "system-call-count-total", total);
		j_obj_new_double_add(j_syscall_info, "system-call-count-rate-total",
			(double)total / duration);
	}
#endif

	list_free(&sorted, NULL);
}

/*
 *  syscall_count_timeout
 *	gather stats on timeout
 */
static void syscall_count_timeout(
	syscall_info_t *s,
	const double timeout,
	const double threshold)
{
	double t = BUCKET_START;
	int bucket = 0;

	while ((t <= timeout) && (bucket < MAX_BUCKET - 1)) {
		bucket++;
		t *= 10;
	}

	s->poll_count++;

	/*  Indefinite waits we ignore in the stats */
	if (timeout < 0.0) {
		s->poll_infinite++;
		return;
	}

	if (s->poll_min < 0.0) {
		s->poll_min = timeout;
		s->poll_max = timeout;
	} else {
		if (s->poll_min > timeout)
			s->poll_min = timeout;
		if (s->poll_max < timeout)
			s->poll_max = timeout;
	}

	if (timeout == 0.0) {
		s->poll_zero++;
		s->poll_too_low++;
		return;
	}

	s->poll_total += timeout;
	s->bucket[bucket]++;

	if (timeout <= threshold)
		s->poll_too_low++;
}

/*
 *  syscall_get_arg_data()
 *	gather dereferenced arg data
 */
static void syscall_get_arg_data(
	const unsigned long addr,
	const pid_t pid,
	void *data,
	const size_t len)
{
	size_t i, n = (len + sizeof(unsigned long) - 1) / sizeof(unsigned long);
	unsigned long tmpdata[n];

	for (i = 0; i < n; i++)
		tmpdata[i] = ptrace(PTRACE_PEEKDATA, pid,
				addr + (sizeof(unsigned long) * i), NULL);
	memcpy(data, tmpdata, len);
}

/*
 *  syscall_timespec_timeout()
 *	keep tally of timespec timeouts
 */
static void syscall_timespec_timeout(
	const syscall_t *sc,
	syscall_info_t *s,
	const pid_t pid,
	const double threshold,
	double *ret_timeout)
{
	unsigned long args[sc->arg + 1];
	struct timespec timeout;

	syscall_get_args(pid, sc->arg, args);
	if (args[sc->arg] == 0) {
		*ret_timeout = -1.0;	/* block indefinitely, flagged with -ve timeout */
	} else {
		syscall_get_arg_data(args[sc->arg], pid, &timeout, sizeof(timeout));
		*ret_timeout = timeout.tv_sec + (timeout.tv_nsec / 1000000000.0);
	}

	syscall_count_timeout(s, *ret_timeout, threshold);
}

/*
 *  syscall_timeval_timeout()
 *     keep tally of timeval timeouts
 */
static void syscall_timeval_timeout(
	const syscall_t *sc,
	syscall_info_t *s,
	const pid_t pid,
	const double threshold,
	double *ret_timeout)
{
	unsigned long args[sc->arg + 1];
	struct timeval timeout;

	syscall_get_args(pid, sc->arg, args);
	if (args[sc->arg] == 0) {
	*ret_timeout = -1.0;    /* block indefinitely, flagged with -ve timeout */
	} else {
		syscall_get_arg_data(args[sc->arg], pid, &timeout, sizeof(timeout));
		*ret_timeout = timeout.tv_sec + (timeout.tv_usec / 1000000.0);
	}

	syscall_count_timeout(s, *ret_timeout, threshold);
}


/*
 *  syscall_timeout_millisec()
 *	keep tally of integer millisecond timeouts
 */
static void syscall_timeout_millisec(
	const syscall_t *sc,
	syscall_info_t *s,
	const pid_t pid,
	const double threshold,
	double *ret_timeout)
{
	unsigned long args[sc->arg + 1];

	syscall_get_args(pid, sc->arg, args);
	*ret_timeout = (double)(int)args[sc->arg] / 1000.0;
	syscall_count_timeout(s, *ret_timeout, threshold);
}

/*
 *  syscall_peek_data()
 *	peek data
 */
#ifdef SYS_write
static void *syscall_peek_data(const pid_t pid, const unsigned long addr, const size_t len)
{
	unsigned *data;
	size_t i, n = (len + sizeof(unsigned long) - 1) / sizeof(unsigned long);

	if ((data = calloc(sizeof(unsigned long), n + 1)) == NULL) {
		fprintf(stderr, "Out of memory\n");
		health_check_exit(EXIT_FAILURE);
	}

	for (i = 0; i < n; i++)
		data[i] = ptrace(PTRACE_PEEKDATA, pid,
				addr + (sizeof(unsigned long) * i), NULL);

	*((char *)data + len) = 0;
	return (void *)data;
}

/*
 *  syscall_wakelock_free()
 *	free a wakelock info struct from list
 */
static void syscall_wakelock_free(void *ptr)
{
	syscall_wakelock_info_t *info = (syscall_wakelock_info_t *)ptr;

	free(info->lockname);
	free(info);
}

/*
 *  syscall_wakelock_fd_cache_free()
 *
 */
static void syscall_wakelock_fd_cache_free(void)
{
	int i;

	for (i = 0; i < HASH_TABLE_SIZE; i++) {
		fd_cache_t *next, *fc = fd_cache[i];

		while (fc) {
			next = fc->next;
			free(fc->filename);
			free(fc);
			fc = next;
		}
	}
}


/*
 *  syscall_close_args()
 *	keep track of wakelock closes
 */
static void syscall_close_args(
	const syscall_t *sc,
	syscall_info_t *s,
	const pid_t pid,
	const double threshold,
	double *ret_timeout)
{
	unsigned long args[sc->arg + 1];
	fd_cache_t *fc;
	unsigned long h;
	int fd;

	(void)s;
	(void)threshold;
	(void)ret_timeout;

	if (!(opt_flags & OPT_WAKELOCKS_HEAVY))
		return;

	syscall_get_args(pid, sc->arg, args);
	fd = (int)args[0];
	h = hash_fd(pid, fd);

	for (fc = fd_cache[h]; fc; fc = fc->next) {
		if (fc->pid == pid && fc->fd == fd) {
			pthread_mutex_lock(&fc->mutex);
			free(fc->filename);
			fc->filename = NULL;
			pthread_mutex_unlock(&fc->mutex);
			return;
		}
	}
}

/*
 *  syscall_write_args()
 *	keep track of wakelock writes
 */
static void syscall_write_args(
	const syscall_t *sc,
	syscall_info_t *s,
	const pid_t pid,
	const double threshold,
	double *ret_timeout)
{
	unsigned long args[sc->arg + 1];
	fd_cache_t *fc;
	unsigned long h;
	int fd;

	if (!(opt_flags & OPT_WAKELOCKS_HEAVY))
		return;

	(void)s;
	(void)threshold;
	(void)ret_timeout;

	syscall_get_args(pid, sc->arg, args);
	fd = (int)args[0];
	h = hash_fd(pid, fd);

	for (fc = fd_cache[h]; fc; fc = fc->next) {
		if (fc->pid == pid && fc->fd == fd)
			break;
	}
	if (fc == NULL) {
		if ((fc = calloc(1, sizeof(*fc))) == NULL) {
			fprintf(stderr, "Out of memory\n");
			health_check_exit(EXIT_FAILURE);
		}
		fc->pid = pid;
		fc->fd = fd;
		fc->filename = fnotify_get_filename(pid, fd);
		if (fc->filename == NULL) {
			fprintf(stderr, "Out of memory\n");
			health_check_exit(EXIT_FAILURE);
		}
		pthread_mutex_init(&fc->mutex, NULL);
		fc->next = fd_cache[h];
		fd_cache[h] = fc;
	} else {
		/*
		 * We've found a cached file, but it may be null if closed
		 * so check for this and re-refetch name if it was closed
		 */
		pthread_mutex_lock(&fc->mutex);
		if (fc->filename == NULL) {
			fc->filename = fnotify_get_filename(pid, fd);
			if (fc->filename == NULL) {
				pthread_mutex_unlock(&fc->mutex);
				fprintf(stderr, "Out of memory\n");
				health_check_exit(EXIT_FAILURE);
			}
		}
		pthread_mutex_unlock(&fc->mutex);
	}

	pthread_mutex_lock(&fc->mutex);
	if (!strcmp(fc->filename, "/sys/power/wake_lock") ||
	    !strcmp(fc->filename, "/sys/power/wake_unlock")) {
		unsigned long addr = args[1];
		size_t count = (size_t)args[2];
		char *lockname = syscall_peek_data(pid, addr, count);
		syscall_wakelock_info_t *info;

		if ((info = calloc(1, sizeof(*info))) == NULL) {
			pthread_mutex_unlock(&fc->mutex);
			fprintf(stderr, "Out of memory\n");
			health_check_exit(EXIT_FAILURE);
		}

		info->pid = pid;
		info->lockname = lockname;
		info->locked = strcmp(fc->filename, "/sys/power/wake_unlock");
		gettimeofday(&info->tv, NULL);

		list_append(&syscall_wakelocks, info);
	}
	pthread_mutex_unlock(&fc->mutex);
}
#endif

/*
 *  syscall_wakelock_cmp()
 *	sorted wakelock list name compare
 */
static int syscall_wakelock_cmp(const void *data1, const void *data2)
{
	return strcmp((char *)data1, (char *)data2);
}

/*
 *  syscall_timeval_to_double()
 *	convert timeval time to double
 */
static inline double syscall_timeval_to_double(struct timeval *tv)
{
	return (double)tv->tv_sec +
	       ((double)tv->tv_usec) / 1000000.0;
}


void syscall_wakelock_names_by_pid(pid_t pid, list_t *wakelock_names)
{
	link_t *l, *ln;

	for (l = syscall_wakelocks.head; l; l = l->next) {
		syscall_wakelock_info_t *info = (syscall_wakelock_info_t *)l->data;
		if (info->pid == pid) {
			bool found = false;
			for (ln = wakelock_names->head; ln; ln = ln->next) {
				char *lockname = (char *)ln->data;
				if (!strcmp(lockname, info->lockname)) {
					found = true;
					break;
				}
			}
			if (!found)
				list_add_ordered(wakelock_names, info->lockname, syscall_wakelock_cmp);
		}
	}
}

/*
 *  syscall_dump_wakelocks()
 *	dump wakelock activity
 */
void syscall_dump_wakelocks(json_object *j_tests, const double duration, list_t *pids)
{
	link_t *lp;
	uint64_t total_locked = 0, total_unlocked = 0;
	uint32_t total_count = 0;
	double total_locked_duration = 0.0;

	(void)j_tests;

	if (!(opt_flags & OPT_WAKELOCKS_HEAVY))
		return;

	printf("Wakelock operations by wakelock:\n");
	if (!syscall_wakelocks.head) {
		printf(" None.\n");
		return;
	}

	printf("  PID  Process              Wakelock             Locks  Unlocks  Locks    Unlocks  Lock Duration\n");
	printf("%65s%s", "", "Per Sec  Per Sec  (Average Sec)\n");
	for (lp = pids->head; lp; lp = lp->next) {
		link_t *ln;
		list_t wakelock_names;
		proc_info_t *p = (proc_info_t *)lp->data;

		list_init(&wakelock_names);

		syscall_wakelock_names_by_pid(p->pid, &wakelock_names);

		for (ln = wakelock_names.head; ln; ln = ln->next) {
			char *lockname = (char *)ln->data;
			uint64_t locked = 0, unlocked = 0;
			double locked_time = -1.0, unlocked_time;
			double locked_duration = 0.0;
			uint32_t count = 0;
			link_t *ls;

			for (ls = syscall_wakelocks.head; ls; ls = ls->next) {
				syscall_wakelock_info_t *info = (syscall_wakelock_info_t *)ls->data;
				if (info->pid == p->pid && !strcmp(lockname, info->lockname)) {
					if (info->locked) {
						locked++;
						locked_time = syscall_timeval_to_double(&info->tv);
					}
					else {
						unlocked++;
						unlocked_time = syscall_timeval_to_double(&info->tv);
						if (locked_time >= 0.0) {
							count++;
							locked_duration += unlocked_time - locked_time;
						}
					}
				}
			}
			total_locked += locked;
			total_unlocked += unlocked;
			total_count += count;
			total_locked_duration += locked_duration;

			printf(" %5i %-20.20s %-16.16s  %8" PRIu64 " %8" PRIu64 " %8.2f %8.2f %12.5f\n",
				p->pid, p->cmdline, lockname, locked, unlocked,
				(double)locked / duration, (double)unlocked / duration,
				count ? locked_duration / count : 0.0);
		}
		list_free(&wakelock_names, NULL);
	}
	printf(" Total%40s%8" PRIu64 " %8" PRIu64 " %8.2f %8.2f %12.5f\n", "",
		total_locked, total_unlocked,
		(double)total_locked / duration, (double)total_unlocked / duration,
		total_count ? total_locked_duration / total_count : 0.0);
	printf("\n");

	if (opt_flags & OPT_VERBOSE) {
		link_t *ls;

		printf("Verbose Dump of Wakelock Actions:\n");
		printf("  PID  Wakelock         Date     Time            Action   Duration (Secs)\n");
		for (ls = syscall_wakelocks.head; ls; ls = ls->next) {
			char buf[64];
			syscall_wakelock_info_t *info = (syscall_wakelock_info_t *)ls->data;
			time_t whence_time = (time_t)info->tv.tv_sec;
			struct tm *whence_tm = localtime(&whence_time);

			strftime(buf, sizeof(buf), "%x %X", whence_tm);

			if (info->locked) {
				link_t *l;

				for (l = ls; l; l = l->next) {
					syscall_wakelock_info_t *info2 = (syscall_wakelock_info_t *)l->data;

					if (info->pid == info2->pid &&
					    !info2->locked &&
					    !strcmp(info->lockname, info2->lockname)) {
						info2->paired = info;
						break;
					}
				}
			}

			if (info->paired) {
				double locked_time = syscall_timeval_to_double(&info->paired->tv);
				double unlocked_time = syscall_timeval_to_double(&info->tv);
				printf(" %5i %-16.16s %s.%06d %-8.8s %f\n",
					info->pid, info->lockname, buf, (int)info->tv.tv_usec,
					info->locked ? "Locked" : "Unlocked",
					unlocked_time - locked_time);
			} else {
				printf(" %5i %-16.16s %s.%06d %-8.8s\n",
					info->pid, info->lockname, buf, (int)info->tv.tv_usec,
					info->locked ? "Locked" : "Unlocked");
			}
		}
	}
}

/*
 *  syscall_timeout_to_human_time()
 *	convert timeout time into something human readable
 */
static char *syscall_timeout_to_human_time(
	const double timeout,
	const bool end,
	char *buffer,
	const size_t len)
{
	char *units[] = { "sec", "msec", "usec", "nsec", "psec" };
	int i;
	double t = timeout;

	for (i = 0; t != 0.0 && t < 0.99999; i++)
		t *= 1000.0;

	if (end) {
		if (t - 0.1 < 0.99999) {
			t *= 1000.0;
			i++;
		}
		t -= 0.1;
	}
	snprintf(buffer, len, "%5.1f", t);
	return units[i];
}

/*
 *  syscall_dump_pollers()
 *	dump polling syscall abusers
 */
void syscall_dump_pollers(json_object *j_tests, const double duration)
{
	int i;
	list_t sorted;
	link_t *l;
#ifndef JSON_OUTPUT
	(void)j_tests;
#endif

	list_init(&sorted);

	for (i = 0; i < HASH_TABLE_SIZE; i++) {
		syscall_info_t *s;

		for (s = syscall_info[i]; s; s = s->next) {
			if (syscalls[s->syscall].check_func) {
				list_add_ordered(&sorted, s, syscall_count_cmp);
				break;
			}
		}
	}

	if (sorted.head) {
#ifdef JSON_OUTPUT
		json_object *j_poll_test;
#endif
		json_object *j_pollers = NULL;

		if (!(opt_flags & OPT_BRIEF)) {
			double prev, bucket;
			char tmp[64], *units;
			double total_rate = 0.0;
			uint64_t poll_infinite = 0, poll_zero = 0, count = 0;

			printf("Top polling system calls:\n");
			printf("  PID  Process              Syscall             Rate/Sec   Infinite   Zero     Minimum    Maximum    Average\n");
			printf("                                                           Timeouts Timeouts   Timeout    Timeout    Timeout\n");
			for (l = sorted.head; l; l = l->next) {
				syscall_info_t *s = (syscall_info_t *)l->data;
				syscall_name(s->syscall, tmp, sizeof(tmp));
				double rate = (double)s->count / duration;

				printf(" %5i %-20.20s %-17.17s %12.4f %8" PRIu64 " %8" PRIu64,
					s->proc->pid, s->proc->cmdline, tmp, rate,
					s->poll_infinite, s->poll_zero);
				if (s->poll_count) {
					char min_timeout[64], max_timeout[64], avg_timeout[64];

					units = syscall_timeout_to_human_time(s->poll_min < 0.0 ? 0.0 : s->poll_min, false, tmp, sizeof(tmp));
					snprintf(min_timeout, sizeof(min_timeout), "%s %-4s", tmp, units);
					units = syscall_timeout_to_human_time(s->poll_max < 0.0 ? 0.0 : s->poll_max, false, tmp, sizeof(tmp));
					snprintf(max_timeout, sizeof(max_timeout), "%s %-4s", tmp, units);
					units = syscall_timeout_to_human_time(s->poll_total / (double)s->count, false, tmp, sizeof(tmp));
					snprintf(avg_timeout, sizeof(avg_timeout), "%s %-4s", tmp, units);

					printf(" %10s %10s %10s", min_timeout, max_timeout, avg_timeout);
				} else {
					printf(" %-10s %-10s %-10s", "    n/a", "    n/a", "    n/a");
				}
				printf("\n");

				total_rate += rate;
				poll_infinite += s->poll_infinite;
				poll_zero += s->poll_zero;
				count++;
			}
			if (count > 1)
				printf(" %-45.45s%12.4f %8" PRIu64 " %8" PRIu64 "\n", "Total",
					total_rate, poll_infinite, poll_zero);

#ifdef JSON_OUTPUT
			if (j_tests) {
				json_object *j_syscall, *j_syscall_infos, *j_syscall_info;

				j_obj_obj_add(j_tests, "polling-system-calls", (j_syscall = j_obj_new_obj()));
                		j_obj_obj_add(j_syscall, "polling-system-calls-per-process", (j_syscall_infos = j_obj_new_array()));
				for (count = 0, l = sorted.head; l; l = l->next) {
					syscall_info_t *s = (syscall_info_t *)l->data;
					syscall_name(s->syscall, tmp, sizeof(tmp));
					double rate = (double)s->count / duration;
					count += s->count;

					j_syscall_info = j_obj_new_obj();
					j_obj_new_int32_add(j_syscall_info, "pid", s->proc->pid);
					j_obj_new_int32_add(j_syscall_info, "ppid", s->proc->ppid);
					j_obj_new_int32_add(j_syscall_info, "is_thread", s->proc->is_thread);
					j_obj_new_string_add(j_syscall_info, "name", s->proc->cmdline);
					j_obj_new_string_add(j_syscall_info, "system-call", tmp);
					j_obj_new_int64_add(j_syscall_info, "system-call-count", s->count);
					j_obj_new_double_add(j_syscall_info, "system-call-rate", rate);
					j_obj_new_int64_add(j_syscall_info, "poll-count-infinite-timeout", s->poll_infinite);
					j_obj_new_int64_add(j_syscall_info, "poll-count-zero-timeout", s->poll_zero);
					j_obj_new_double_add(j_syscall_info, "poll-minimum-timeout-millisecs", s->poll_min < 0.0 ? 0.0 : s->poll_min);
					j_obj_new_double_add(j_syscall_info, "poll-maximum-timeout-millisecs", s->poll_max < 0.0 ? 0.0 : s->poll_max);
					j_obj_new_double_add(j_syscall_info, "poll-average-timeout-millisecs", s->poll_total / (double)s->count);
					j_obj_array_add(j_syscall_infos, j_syscall_info);
				}
				j_obj_obj_add(j_syscall, "polling-system-calls-total", (j_syscall_info = j_obj_new_obj()));
				j_obj_new_int64_add(j_syscall_info, "system-call-count-total", count);
				j_obj_new_double_add(j_syscall_info, "system-call-rate-total", (double)count / duration);
				j_obj_new_int64_add(j_syscall_info, "poll-count-infinite-total", (int64_t)poll_infinite);
				j_obj_new_int64_add(j_syscall_info, "poll-count-zero-total", poll_zero);
			}
#endif

			printf("\nDistribution of poll timeout times:\n");

			printf("%50.50s", "");
			for (prev = 0.0, bucket = BUCKET_START, i = 0; i < MAX_BUCKET; i++, bucket *= 10.0) {
				(void)syscall_timeout_to_human_time(prev, false, tmp, sizeof(tmp));
				printf(" %6s", i == 0 ? "" : tmp);
				prev = bucket;
			}
			printf("\n");
			printf("%50.50s", "");
			for (bucket = BUCKET_START, i = 0; i < MAX_BUCKET; i++) {
				if (i == 0)
					printf("  up to");
				else if (i == MAX_BUCKET - 1)
					printf(" or more");
				else
					printf("    to ");
			}
			printf("\n");

			printf("%46.46sZero", "");
			for (bucket = BUCKET_START, i = 0; i < MAX_BUCKET; i++, bucket *= 10.0) {
				(void)syscall_timeout_to_human_time(bucket, true, tmp, sizeof(tmp));
				printf(" %6s", i == (MAX_BUCKET-1) ? "" : tmp);
			}
			printf(" Infinite\n");
			printf("  PID  Process              Syscall            sec");
			for (bucket = BUCKET_START, i = 0; i < MAX_BUCKET; i++, bucket *= 10.0) {
				units = syscall_timeout_to_human_time(bucket, true, tmp, sizeof(tmp));
				printf(" %6s", units);
			}
			printf("   Wait\n");
			for (l = sorted.head; l; l = l->next) {
				syscall_info_t *s = (syscall_info_t *)l->data;

				syscall_name(s->syscall, tmp, sizeof(tmp));
				printf(" %5u %-20.20s %-15.15s %6" PRIu64, s->proc->pid, s->proc->cmdline, tmp, s->poll_zero);
				for (i = 0; i < MAX_BUCKET; i++) {
					if (s->bucket[i])
						printf(" %6" PRIu64, s->bucket[i]);
					else
						printf("     - ");
				}
				printf(" %6" PRIu64, s->poll_infinite);
				printf("\n");
			}
			printf("\n");
		}

#ifdef JSON_OUTPUT
		if (j_tests) {
			j_obj_obj_add(j_tests, "polling-system-call-returns", (j_poll_test = j_obj_new_obj()));
                	j_obj_obj_add(j_poll_test, "polling-system-call-returns-per-process", (j_pollers = j_obj_new_array()));
		}
#endif
		printf("Polling system call analysis:\n");
		for (l = sorted.head; l; l = l->next) {
			syscall_info_t *s = (syscall_info_t *)l->data;
			if (syscall_valid(s->syscall)) {
				syscall_t *sc = &syscalls[s->syscall];
				if (sc->check_ret)
					sc->check_ret(j_pollers, sc, s);
			}
		}
		if (!info_emit)
			printf(" No bad polling discovered.\n");
		printf("\n");
	}
	list_free(&sorted, NULL);
}

/*
 *  syscall_account_return()
 *	if the system call has return check handler then
 *	fetch return value from syscall and add it to
 *	list of returns
 */
static void syscall_account_return(
	syscall_info_t *s,
	const int pid,
	const int syscall,
	const double timeout)
{
	if (syscall_valid(syscall)) {
		syscall_t *sc = &syscalls[syscall];
		if (sc->check_ret) {
			syscall_return_info_t *info;
			int ret;

			if (syscall_get_return(pid, &ret) < 0)
				return;

			if (s) {
				if ((info = (syscall_return_info_t *)calloc(1, sizeof(*info))) == NULL) {
					fprintf(stderr, "Out of memory\n");
					health_check_exit(EXIT_FAILURE);
				}
				info->timeout = timeout;
				info->ret = ret;
				list_append(&s->return_history, info);
			}
		}
	}
}

/*
 *  syscall_count()
 *	tally syscall usage
 */
static syscall_info_t *syscall_count_usage(
	const pid_t pid,
	const int syscall,
	double *timeout)
{
	unsigned long h = hash_syscall(pid, syscall);
	syscall_info_t *s = NULL;
	syscall_t *sc;
	bool found = false;
	sc = syscall_valid(syscall) ? &syscalls[syscall] : NULL;

	if (!sc)
		return NULL;

	if (sc->do_accounting) {
		*timeout = -1.0;
		for (s = syscall_info[h]; s; s = s->next) {
			if ((s->syscall == syscall) && (s->proc->pid == pid)) {
				s->count++;
				found = true;
				break;
			}
		}

		if (!found) {
			/*
			 *  Doesn't exist, create new one
			 */
			if ((s = calloc(1, sizeof(*s))) == NULL) {
				fprintf(stderr, "Cannot allocate syscall hash item\n");
				health_check_exit(EXIT_FAILURE);
			}
			s->syscall = syscall;
			s->proc = proc_cache_find_by_pid(pid);
			s->count = 1;
			s->poll_zero = 0;
			s->poll_infinite = 0;
			s->poll_count = 0;
			s->poll_min = -1.0;
			s->poll_max = -1.0;
			s->poll_total = 0;
			s->poll_too_low = 0;
			list_init(&s->return_history);

			s->next = syscall_info[h];
			syscall_info[h] = s;
		}
	}
	if (sc->check_func) {
		if (++syscall_count >= opt_max_syscalls)
			keep_running = false;
		sc->check_func(sc, s, pid, *(sc->threshold), timeout);
	}

	return s;
}

void syscall_handle_syscall(syscall_context_t *ctxt)
{
	if (syscall_is_call_entry(ctxt->pid)) {
		if (syscall_get_call(ctxt->pid, &ctxt->syscall) == -1) {
			ctxt->syscall_info = NULL;
			ctxt->timeout = 0.0;
			return;
		} else {
			ctxt->syscall_info = syscall_count_usage(ctxt->pid, ctxt->syscall, &ctxt->timeout);
			return;
		}
	} else {
		if (ctxt->syscall_info != NULL)
			syscall_account_return(ctxt->syscall_info, ctxt->pid, ctxt->syscall, ctxt->timeout);
		/* We've got a return, so clear info for next syscall */
		ctxt->syscall = -1;
		ctxt->syscall_info = NULL;
		ctxt->timeout = 0.0;
	}
}

void syscall_handle_event(syscall_context_t *ctxt, int event)
{
	if (event == PTRACE_EVENT_CLONE ||
	    event == PTRACE_EVENT_FORK ||
	    event == PTRACE_EVENT_VFORK) {
		unsigned long msg;
		pid_t child;
		proc_info_t *p;

		ptrace(PTRACE_GETEVENTMSG, ctxt->pid, 0, &msg);
		child = (pid_t)msg;

#if SYSCALL_DEBUG
		if (event == PTRACE_EVENT_CLONE)
			printf("PID %d is a clone\n", child);
		if (event == PTRACE_EVENT_FORK)
			printf("PID %d forked\n", child);
		if (event == PTRACE_EVENT_VFORK)
			printf("PID %d vforked\n", child);
#endif

		if ((p = proc_cache_add(child, 0, event == PTRACE_EVENT_CLONE)) != NULL) {
			proc_pids_add_proc(__pids, p);
			mem_get_by_proc(p, PROC_START);
			cpustat_get_by_proc(p, PROC_START);
			ctxt_switch_get_by_proc(p, PROC_START);
		}
		net_connection_pid(child);	/* Update net connections on new process */
	}
}

void syscall_handle_trap(syscall_context_t *ctxt)
{
	siginfo_t siginfo;

	if (ptrace(PTRACE_GETSIGINFO, ctxt->pid, 0, &siginfo) == -1) {
		fprintf(stderr, "Cannot get signal info on pid %d\n", ctxt->pid);
		return;
	}

	if (siginfo.si_code == SIGTRAP) {
		syscall_handle_syscall(ctxt);
	} else {
		/* printf("breakpoint on PID %d\n", ctxt->pid); */
	}
}

int syscall_handle_stop(syscall_context_t *ctxt, const int status)
{
	int event = status >> 16;
	int sig = WSTOPSIG(status);
			
	if (sig == SIGTRAP) {
		if (event) {
			syscall_handle_event(ctxt, event);
		} else {
			syscall_handle_trap(ctxt);
		}
	} else if (sig == (SIGTRAP | 0x80)) {
		syscall_handle_syscall(ctxt);
	} else if ((sig != SIGCHLD) && (sig != SIGSTOP)) {
		return sig;
	}
	return 0;
}

/*
 *  syscall_context_find_by_pid()
 * 	find syscall context by pid
 */
syscall_context_t *syscall_context_find_by_pid(const pid_t pid)
{
	link_t *l;
	syscall_context_t *ctxt;

	for (l = syscall_contexts.head; l; l = l->next) {
		ctxt = (syscall_context_t *)l->data;
		if (ctxt->pid == pid) {
			return ctxt;
		}
	}

	return NULL;
}

static syscall_context_t *syscall_get_context(pid_t pid)
{
	syscall_context_t *ctxt;

	ctxt = syscall_context_find_by_pid(pid);
	if (ctxt == NULL) {
		if ((ctxt = calloc(1, sizeof(*ctxt))) == NULL) {
			fprintf(stderr, "Out of memory allocating tracing context\n");
			return NULL;
		}
		ctxt->pid = pid;
		ctxt->proc = proc_cache_find_by_pid(pid);
		ctxt->timeout = 0.0;
		ctxt->syscall = -1;
		ctxt->syscall_info = NULL;
		ctxt->alive = true;
		list_append(&syscall_contexts, ctxt);
		procs_traced++;
	}
	return ctxt;
}

/*
 *  syscall_trace()
 *	syscall tracer, run in a pthread
 */
void *syscall_trace(void *arg)
{
	syscall_context_t *ctxt;
	int status;
	link_t *l;

	(void)arg;

	for (l = syscall_contexts.head; l; l = l->next) {
		ctxt = (syscall_context_t *)l->data;	
		ptrace(PTRACE_ATTACH, ctxt->pid, 0, 0);
		ptrace(PTRACE_SETOPTIONS, ctxt->pid, 0,
			PTRACE_O_TRACESYSGOOD |
			PTRACE_O_TRACECLONE | 
			PTRACE_O_TRACEFORK |
			PTRACE_O_TRACEVFORK);
		procs_traced++;
	}

	while (keep_running && procs_traced > 0) {
		int sig = 0;
		pid_t pid;

		errno = 0;
		if ((pid = waitpid(-1, &status, __WALL)) == -1) {
			if (errno == ECHILD)
				break;
		}

		if ((ctxt = syscall_get_context(pid)) == NULL) {
			fprintf(stderr, "Out of memory allocating tracing context\n");
			break;
		}

		if (WIFSTOPPED(status)) {
			sig = syscall_handle_stop(ctxt, status);
		} else if (WIFEXITED(status)) {
			if (ctxt->proc) {
				/*
				 *  We need to probably catch exit in the system call
			 	 *  so we can do accounting, it seems that the proc files
				 *  disappear too early.
				 */
				cpustat_get_by_proc(ctxt->proc, PROC_FINISH);
				ctxt_switch_get_by_proc(ctxt->proc, PROC_FINISH);
				mem_get_by_proc(ctxt->proc, PROC_FINISH);
			}
			ctxt->alive = false;
			procs_traced--;
		} 
		else if (WIFSIGNALED(status)) {
			/*
			 *  In an ideal world we could find the final
			 *  stats *before* it died and update CPU stat etc
			 *  TODO: See if we can find out final state before
			 *  signalled.
			 */
			if (WTERMSIG(status) == SIGKILL) {
				/* It died */
				printf("Process %d received SIGKILL during monitoring.\n", pid);
				ctxt->alive = false;
				procs_traced--;
			}
		} 
#if SYSCALL_DEBUG
		else if (WIFCONTINUED(status)) {
			printf("Continued %d\n", ctxt->pid);
		} else {
			printf("Unexpected status %d for PID %d\n", status, ctxt->pid);
		}
#endif
		ptrace(PTRACE_SYSCALL, ctxt->pid, 0, sig);
	}

	for (l = syscall_contexts.head; l; l = l->next) {
		ctxt = (syscall_context_t *)l->data;
		if (ctxt->alive) {
			ptrace(PTRACE_CONT, ctxt->pid, 0, 0);
			ptrace(PTRACE_DETACH, ctxt->pid, 0, 0);
		}
	}

	keep_running = false;
	pthread_exit(0);
}

void syscall_init(void)
{
	list_init(&syscall_wakelocks);
	list_init(&syscall_contexts);
}

void syscall_cleanup(void)
{
	pthread_cancel(syscall_tracer);
	pthread_join(syscall_tracer, NULL);

	list_free(&syscall_wakelocks, syscall_wakelock_free);
	list_free(&syscall_contexts, free);
	syscall_wakelock_fd_cache_free();
	syscall_hashtable_free();
}

int syscall_trace_proc(list_t *pids)
{
	link_t *l;

	__pids = pids;

	for (l = pids->head; l; l = l->next) {
		proc_info_t *p = (proc_info_t *)l->data;
		(void)syscall_get_context(p->pid);
	}

	if (pthread_create(&syscall_tracer, NULL, syscall_trace, NULL) < 0) {
		fprintf(stderr, "Failed to create tracing thread\n");
		return -1;
	}
	return 0;
}

/* system call table */
syscall_t syscalls[] = {
#ifdef SYS_setup
	SYSCALL(setup),
#endif
#ifdef SYS_accept
	SYSCALL(accept),
#endif
#ifdef SYS_accept4
	SYSCALL(accept4),
#endif
#ifdef SYS_access
	SYSCALL(access),
#endif
#ifdef SYS_acct
	SYSCALL(acct),
#endif
#ifdef SYS_add_key
	SYSCALL(add_key),
#endif
#ifdef SYS_adjtimex
	SYSCALL(adjtimex),
#endif
#ifdef SYS_afs_syscall
	SYSCALL(afs_syscall),
#endif
#ifdef SYS_alarm
	SYSCALL(alarm),
#endif
#ifdef SYS_arch_prctl
	SYSCALL(arch_prctl),
#endif
#ifdef SYS_bdflush
	SYSCALL(bdflush),
#endif
#ifdef SYS_bind
	SYSCALL(bind),
#endif
#ifdef SYS_break
	SYSCALL(break),
#endif
#ifdef SYS_brk
	SYSCALL(brk),
#endif
#ifdef SYS_capget
	SYSCALL(capget),
#endif
#ifdef SYS_capset
	SYSCALL(capset),
#endif
#ifdef SYS_chdir
	SYSCALL(chdir),
#endif
#ifdef SYS_chmod
	SYSCALL(chmod),
#endif
#ifdef SYS_chown
	SYSCALL(chown),
#endif
#ifdef SYS_chown32
	SYSCALL(chown32),
#endif
#ifdef SYS_chroot
	SYSCALL(chroot),
#endif
#ifdef SYS_clock_adjtime
	SYSCALL(clock_adjtime),
#endif
#ifdef SYS_clock_getres
	SYSCALL(clock_getres),
#endif
#ifdef SYS_clock_gettime
	SYSCALL(clock_gettime),
#endif
#ifdef SYS_clock_nanosleep
	SYSCALL_TIMEOUT(clock_nanosleep, 2, syscall_timespec_timeout, syscall_nanosleep_generic_ret),
#endif
#ifdef SYS_clock_settime
	SYSCALL(clock_settime),
#endif
#ifdef SYS_clone
	SYSCALL(clone),
#endif
#ifdef SYS_close
	SYSCALL_CHKARGS(close, 0, syscall_close_args, NULL),
#endif
#ifdef SYS_connect
	SYSCALL_TIMEOUT(connect, 0, syscall_connect, syscall_connect_ret),
#endif
#ifdef SYS_creat
	SYSCALL(creat),
#endif
#ifdef SYS_create_module
	SYSCALL(create_module),
#endif
#ifdef SYS_delete_module
	SYSCALL(delete_module),
#endif
#ifdef SYS_dup
	SYSCALL(dup),
#endif
#ifdef SYS_dup2
	SYSCALL(dup2),
#endif
#ifdef SYS_dup3
	SYSCALL(dup3),
#endif
#ifdef SYS_epoll_create
	SYSCALL(epoll_create),
#endif
#ifdef SYS_epoll_create1
	SYSCALL(epoll_create1),
#endif
#ifdef SYS_epoll_ctl
	SYSCALL(epoll_ctl),
#endif
#ifdef SYS_epoll_ctl_old
	SYSCALL(epoll_ctl_old),
#endif
#ifdef SYS_epoll_pwait
	SYSCALL_TIMEOUT(epoll_pwait, 3, syscall_timeout_millisec, syscall_poll_generic_ret),
#endif
#ifdef SYS_epoll_wait
	SYSCALL_TIMEOUT(epoll_wait, 3, syscall_timeout_millisec, syscall_poll_generic_ret),
#endif
#ifdef SYS_epoll_wait_old
	SYSCALL(epoll_wait_old),
#endif
#ifdef SYS_eventfd
	SYSCALL(eventfd),
#endif
#ifdef SYS_eventfd2
	SYSCALL(eventfd2),
#endif
#ifdef SYS_execve
	SYSCALL(execve),
#endif
#ifdef SYS_exit
	SYSCALL(exit),
#endif
#ifdef SYS_exit_group
	SYSCALL(exit_group),
#endif
#ifdef SYS_faccessat
	SYSCALL(faccessat),
#endif
#ifdef SYS_fadvise64
	SYSCALL(fadvise64),
#endif
#ifdef SYS_fadvise64_64
	SYSCALL(fadvise64_64),
#endif
#ifdef SYS_fallocate
	SYSCALL(fallocate),
#endif
#ifdef SYS_fanotify_init
	SYSCALL(fanotify_init),
#endif
#ifdef SYS_fanotify_mark
	SYSCALL(fanotify_mark),
#endif
#ifdef SYS_fchdir
	SYSCALL(fchdir),
#endif
#ifdef SYS_fchmod
	SYSCALL(fchmod),
#endif
#ifdef SYS_fchmodat
	SYSCALL(fchmodat),
#endif
#ifdef SYS_fchown
	SYSCALL(fchown),
#endif
#ifdef SYS_fchown32
	SYSCALL(fchown32),
#endif
#ifdef SYS_fchownat
	SYSCALL(fchownat),
#endif
#ifdef SYS_fcntl
	SYSCALL(fcntl),
#endif
#ifdef SYS_fcntl64
	SYSCALL(fcntl64),
#endif
#ifdef SYS_fdatasync
	SYSCALL(fdatasync),
#endif
#ifdef SYS_fgetxattr
	SYSCALL(fgetxattr),
#endif
#ifdef SYS_finit_module
	SYSCALL(finit_module),
#endif
#ifdef SYS_flistxattr
	SYSCALL(flistxattr),
#endif
#ifdef SYS_flock
	SYSCALL(flock),
#endif
#ifdef SYS_fork
	SYSCALL(fork),
#endif
#ifdef SYS_fremovexattr
	SYSCALL(fremovexattr),
#endif
#ifdef SYS_fsetxattr
	SYSCALL(fsetxattr),
#endif
#ifdef SYS_fstat
	SYSCALL(fstat),
#endif
#ifdef SYS_fstat64
	SYSCALL(fstat64),
#endif
#ifdef SYS_fstatat64
	SYSCALL(fstatat64),
#endif
#ifdef SYS_fstatfs
	SYSCALL(fstatfs),
#endif
#ifdef SYS_fstatfs64
	SYSCALL(fstatfs64),
#endif
#ifdef SYS_fsync
	SYSCALL(fsync),
#endif
#ifdef SYS_ftime
	SYSCALL(ftime),
#endif
#ifdef SYS_ftruncate
	SYSCALL(ftruncate),
#endif
#ifdef SYS_ftruncate64
	SYSCALL(ftruncate64),
#endif
#ifdef SYS_futex
	SYSCALL(futex),
#endif
#ifdef SYS_futimesat
	SYSCALL(futimesat),
#endif
#ifdef SYS_getcpu
	SYSCALL(getcpu),
#endif
#ifdef SYS_getcwd
	SYSCALL(getcwd),
#endif
#ifdef SYS_getdents
	SYSCALL(getdents),
#endif
#ifdef SYS_getdents64
	SYSCALL(getdents64),
#endif
#ifdef SYS_getegid
	SYSCALL(getegid),
#endif
#ifdef SYS_getegid32
	SYSCALL(getegid32),
#endif
#ifdef SYS_geteuid
	SYSCALL(geteuid),
#endif
#ifdef SYS_geteuid32
	SYSCALL(geteuid32),
#endif
#ifdef SYS_getgid
	SYSCALL(getgid),
#endif
#ifdef SYS_getgid32
	SYSCALL(getgid32),
#endif
#ifdef SYS_getgroups
	SYSCALL(getgroups),
#endif
#ifdef SYS_getgroups32
	SYSCALL(getgroups32),
#endif
#ifdef SYS_getitimer
	SYSCALL(getitimer),
#endif
#ifdef SYS_get_kernel_syms
	SYSCALL(get_kernel_syms),
#endif
#ifdef SYS_get_mempolicy
	SYSCALL(get_mempolicy),
#endif
#ifdef SYS_getpeername
	SYSCALL(getpeername),
#endif
#ifdef SYS_getpgid
	SYSCALL(getpgid),
#endif
#ifdef SYS_getpgrp
	SYSCALL(getpgrp),
#endif
#ifdef SYS_getpid
	SYSCALL(getpid),
#endif
#ifdef SYS_getpmsg
	SYSCALL(getpmsg),
#endif
#ifdef SYS_getppid
	SYSCALL(getppid),
#endif
#ifdef SYS_getpriority
	SYSCALL(getpriority),
#endif
#ifdef SYS_getresgid
	SYSCALL(getresgid),
#endif
#ifdef SYS_getresgid32
	SYSCALL(getresgid32),
#endif
#ifdef SYS_getresuid
	SYSCALL(getresuid),
#endif
#ifdef SYS_getresuid32
	SYSCALL(getresuid32),
#endif
#ifdef SYS_getrlimit
	SYSCALL(getrlimit),
#endif
#ifdef SYS_get_robust_list
	SYSCALL(get_robust_list),
#endif
#ifdef SYS_getrusage
	SYSCALL(getrusage),
#endif
#ifdef SYS_getsid
	SYSCALL(getsid),
#endif
#ifdef SYS_getsockname
	SYSCALL(getsockname),
#endif
#ifdef SYS_getsockopt
	SYSCALL(getsockopt),
#endif
#ifdef SYS_get_thread_area
	SYSCALL(get_thread_area),
#endif
#ifdef SYS_gettid
	SYSCALL(gettid),
#endif
#ifdef SYS_gettimeofday
	SYSCALL(gettimeofday),
#endif
#ifdef SYS_getuid
	SYSCALL(getuid),
#endif
#ifdef SYS_getuid32
	SYSCALL(getuid32),
#endif
#ifdef SYS_getxattr
	SYSCALL(getxattr),
#endif
#ifdef SYS_gtty
	SYSCALL(gtty),
#endif
#ifdef SYS_idle
	SYSCALL(idle),
#endif
#ifdef SYS_init_module
	SYSCALL(init_module),
#endif
#ifdef SYS_inotify_add_watch
	SYSCALL(inotify_add_watch),
#endif
#ifdef SYS_inotify_init
	SYSCALL(inotify_init),
#endif
#ifdef SYS_inotify_init1
	SYSCALL(inotify_init1),
#endif
#ifdef SYS_inotify_rm_watch
	SYSCALL(inotify_rm_watch),
#endif
#ifdef SYS_io_cancel
	SYSCALL(io_cancel),
#endif
#ifdef SYS_ioctl
	SYSCALL(ioctl),
#endif
#ifdef SYS_io_destroy
	SYSCALL(io_destroy),
#endif
#ifdef SYS_io_getevents
	SYSCALL(io_getevents),
#endif
#ifdef SYS_ioperm
	SYSCALL(ioperm),
#endif
#ifdef SYS_iopl
	SYSCALL(iopl),
#endif
#ifdef SYS_ioprio_get
	SYSCALL(ioprio_get),
#endif
#ifdef SYS_ioprio_set
	SYSCALL(ioprio_set),
#endif
#ifdef SYS_io_setup
	SYSCALL(io_setup),
#endif
#ifdef SYS_io_submit
	SYSCALL(io_submit),
#endif
#ifdef SYS_ipc
	SYSCALL(ipc),
#endif
#ifdef SYS_kcmp
	SYSCALL(kcmp),
#endif
#ifdef SYS_kexec_load
	SYSCALL(kexec_load),
#endif
#ifdef SYS_keyctl
	SYSCALL(keyctl),
#endif
#ifdef SYS_kill
	SYSCALL(kill),
#endif
#ifdef SYS_lchown
	SYSCALL(lchown),
#endif
#ifdef SYS_lchown32
	SYSCALL(lchown32),
#endif
#ifdef SYS_lgetxattr
	SYSCALL(lgetxattr),
#endif
#ifdef SYS_link
	SYSCALL(link),
#endif
#ifdef SYS_linkat
	SYSCALL(linkat),
#endif
#ifdef SYS_listen
	SYSCALL(listen),
#endif
#ifdef SYS_listxattr
	SYSCALL(listxattr),
#endif
#ifdef SYS_llistxattr
	SYSCALL(llistxattr),
#endif
#ifdef SYS__llseek
	SYSCALL(_llseek),
#endif
#ifdef SYS_lock
	SYSCALL(lock),
#endif
#ifdef SYS_lookup_dcookie
	SYSCALL(lookup_dcookie),
#endif
#ifdef SYS_lremovexattr
	SYSCALL(lremovexattr),
#endif
#ifdef SYS_lseek
	SYSCALL(lseek),
#endif
#ifdef SYS_lsetxattr
	SYSCALL(lsetxattr),
#endif
#ifdef SYS_lstat
	SYSCALL(lstat),
#endif
#ifdef SYS_lstat64
	SYSCALL(lstat64),
#endif
#ifdef SYS_madvise
	SYSCALL(madvise),
#endif
#ifdef SYS_mbind
	SYSCALL(mbind),
#endif
#ifdef SYS_migrate_pages
	SYSCALL(migrate_pages),
#endif
#ifdef SYS_mincore
	SYSCALL(mincore),
#endif
#ifdef SYS_mkdir
	SYSCALL(mkdir),
#endif
#ifdef SYS_mkdirat
	SYSCALL(mkdirat),
#endif
#ifdef SYS_mknod
	SYSCALL(mknod),
#endif
#ifdef SYS_mknodat
	SYSCALL(mknodat),
#endif
#ifdef SYS_mlock
	SYSCALL(mlock),
#endif
#ifdef SYS_mlockall
	SYSCALL(mlockall),
#endif
#ifdef SYS_mmap
	SYSCALL(mmap),
#endif
#ifdef SYS_mmap2
	SYSCALL(mmap2),
#endif
#ifdef SYS_modify_ldt
	SYSCALL(modify_ldt),
#endif
#ifdef SYS_mount
	SYSCALL(mount),
#endif
#ifdef SYS_move_pages
	SYSCALL(move_pages),
#endif
#ifdef SYS_mprotect
	SYSCALL(mprotect),
#endif
#ifdef SYS_mpx
	SYSCALL(mpx),
#endif
#ifdef SYS_mq_getsetattr
	SYSCALL(mq_getsetattr),
#endif
#ifdef SYS_mq_notify
	SYSCALL(mq_notify),
#endif
#ifdef SYS_mq_open
	SYSCALL(mq_open),
#endif
#ifdef SYS_mq_timedreceive
	SYSCALL_TIMEOUT(mq_timedreceive, 4, syscall_timespec_timeout, syscall_mq_timedreceive_ret),
#endif
#ifdef SYS_mq_timedsend
	SYSCALL_TIMEOUT(mq_timedsend, 4, syscall_timespec_timeout, syscall_mq_timedsend_ret),
#endif
#ifdef SYS_mq_unlink
	SYSCALL(mq_unlink),
#endif
#ifdef SYS_mremap
	SYSCALL(mremap),
#endif
#ifdef SYS_msgctl
	SYSCALL(msgctl),
#endif
#ifdef SYS_msgget
	SYSCALL(msgget),
#endif
#ifdef SYS_msgrcv
	SYSCALL(msgrcv),
#endif
#ifdef SYS_msgsnd
	SYSCALL(msgsnd),
#endif
#ifdef SYS_msync
	SYSCALL(msync),
#endif
#ifdef SYS_munlock
	SYSCALL(munlock),
#endif
#ifdef SYS_munlockall
	SYSCALL(munlockall),
#endif
#ifdef SYS_munmap
	SYSCALL(munmap),
#endif
#ifdef SYS_name_to_handle_at
	SYSCALL(name_to_handle_at),
#endif
#ifdef SYS_nanosleep
	SYSCALL_TIMEOUT(nanosleep, 0, syscall_timespec_timeout, syscall_nanosleep_generic_ret),
#endif
#ifdef SYS_newfstatat
	SYSCALL(newfstatat),
#endif
#ifdef SYS__newselect
	SYSCALL_TIMEOUT(_newselect, 4, syscall_timeval_timeout, syscall_poll_generic_ret),
#endif
#ifdef SYS_nfsservctl
	SYSCALL(nfsservctl),
#endif
#ifdef SYS_nice
	SYSCALL(nice),
#endif
#ifdef SYS_oldfstat
	SYSCALL(oldfstat),
#endif
#ifdef SYS_oldlstat
	SYSCALL(oldlstat),
#endif
#ifdef SYS_oldolduname
	SYSCALL(oldolduname),
#endif
#ifdef SYS_oldstat
	SYSCALL(oldstat),
#endif
#ifdef SYS_olduname
	SYSCALL(olduname),
#endif
#ifdef SYS_open
	SYSCALL(open),
#endif
#ifdef SYS_openat
	SYSCALL(openat),
#endif
#ifdef SYS_open_by_handle_at
	SYSCALL(open_by_handle_at),
#endif
#ifdef SYS_pause
	SYSCALL(pause),
#endif
#ifdef SYS_perf_event_open
	SYSCALL(perf_event_open),
#endif
#ifdef SYS_personality
	SYSCALL(personality),
#endif
#ifdef SYS_pipe
	SYSCALL(pipe),
#endif
#ifdef SYS_pipe2
	SYSCALL(pipe2),
#endif
#ifdef SYS_pivot_root
	SYSCALL(pivot_root),
#endif
#ifdef SYS_poll
	SYSCALL_TIMEOUT(poll, 2, syscall_timeout_millisec, syscall_poll_generic_ret),
#endif
#ifdef SYS_ppoll
	SYSCALL_TIMEOUT(ppoll, 2, syscall_timespec_timeout, syscall_poll_generic_ret),
#endif
#ifdef SYS_prctl
	SYSCALL(prctl),
#endif
#ifdef SYS_pread64
	SYSCALL(pread64),
#endif
#ifdef SYS_preadv
	SYSCALL(preadv),
#endif
#ifdef SYS_prlimit64
	SYSCALL(prlimit64),
#endif
#ifdef SYS_process_vm_readv
	SYSCALL(process_vm_readv),
#endif
#ifdef SYS_process_vm_writev
	SYSCALL(process_vm_writev),
#endif
#ifdef SYS_prof
	SYSCALL(prof),
#endif
#ifdef SYS_profil
	SYSCALL(profil),
#endif
#ifdef SYS_pselect6
	SYSCALL_TIMEOUT(pselect6, 4, syscall_timespec_timeout, syscall_poll_generic_ret),
#endif
#ifdef SYS_ptrace
	SYSCALL(ptrace),
#endif
#ifdef SYS_putpmsg
	SYSCALL(putpmsg),
#endif
#ifdef SYS_pwrite64
	SYSCALL(pwrite64),
#endif
#ifdef SYS_pwritev
	SYSCALL(pwritev),
#endif
#ifdef SYS_query_module
	SYSCALL(query_module),
#endif
#ifdef SYS_quotactl
	SYSCALL(quotactl),
#endif
#ifdef SYS_read
	SYSCALL(read),
#endif
#ifdef SYS_readahead
	SYSCALL(readahead),
#endif
#ifdef SYS_readdir
	SYSCALL(readdir),
#endif
#ifdef SYS_readlink
	SYSCALL(readlink),
#endif
#ifdef SYS_readlinkat
	SYSCALL(readlinkat),
#endif
#ifdef SYS_readv
	SYSCALL(readv),
#endif
#ifdef SYS_reboot
	SYSCALL(reboot),
#endif
#ifdef SYS_recvfrom
	SYSCALL(recvfrom),
#endif
#ifdef SYS_recvmmsg
	SYSCALL_TIMEOUT(recvmmsg, 4, syscall_timespec_timeout, NULL),
#endif
#ifdef SYS_recvmsg
	SYSCALL(recvmsg),
#endif
#ifdef SYS_remap_file_pages
	SYSCALL(remap_file_pages),
#endif
#ifdef SYS_removexattr
	SYSCALL(removexattr),
#endif
#ifdef SYS_rename
	SYSCALL(rename),
#endif
#ifdef SYS_renameat
	SYSCALL(renameat),
#endif
#ifdef SYS_request_key
	SYSCALL(request_key),
#endif
#ifdef SYS_restart_syscall
	SYSCALL(restart_syscall),
#endif
#ifdef SYS_rmdir
	SYSCALL(rmdir),
#endif
#ifdef SYS_rt_sigaction
	SYSCALL(rt_sigaction),
#endif
#ifdef SYS_rt_sigpending
	SYSCALL(rt_sigpending),
#endif
#ifdef SYS_rt_sigprocmask
	SYSCALL(rt_sigprocmask),
#endif
#ifdef SYS_rt_sigqueueinfo
	SYSCALL(rt_sigqueueinfo),
#endif
#ifdef SYS_rt_sigreturn
	SYSCALL(rt_sigreturn),
#endif
#ifdef SYS_rt_sigsuspend
	SYSCALL(rt_sigsuspend),
#endif
#ifdef SYS_rt_sigtimedwait
	SYSCALL_TIMEOUT(rt_sigtimedwait, 2, syscall_timespec_timeout, syscall_poll_generic_ret),
#endif
#ifdef SYS_rt_tgsigqueueinfo
	SYSCALL(rt_tgsigqueueinfo),
#endif
#ifdef SYS_sched_getaffinity
	SYSCALL(sched_getaffinity),
#endif
#ifdef SYS_sched_getparam
	SYSCALL(sched_getparam),
#endif
#ifdef SYS_sched_get_priority_max
	SYSCALL(sched_get_priority_max),
#endif
#ifdef SYS_sched_get_priority_min
	SYSCALL(sched_get_priority_min),
#endif
#ifdef SYS_sched_getscheduler
	SYSCALL(sched_getscheduler),
#endif
#ifdef SYS_sched_rr_get_interval
	SYSCALL(sched_rr_get_interval),
#endif
#ifdef SYS_sched_setaffinity
	SYSCALL(sched_setaffinity),
#endif
#ifdef SYS_sched_setparam
	SYSCALL(sched_setparam),
#endif
#ifdef SYS_sched_setscheduler
	SYSCALL(sched_setscheduler),
#endif
#ifdef SYS_sched_yield
	SYSCALL(sched_yield),
#endif
#ifdef SYS_security
	SYSCALL(security),
#endif
#ifdef SYS_select
	SYSCALL_TIMEOUT(select, 4, syscall_timeval_timeout, syscall_poll_generic_ret),
#endif
#ifdef SYS_semctl
	SYSCALL(semctl),
#endif
#ifdef SYS_semget
	SYSCALL(semget),
#endif
#ifdef SYS_semop
	SYSCALL(semop),
#endif
#ifdef SYS_semtimedop
	SYSCALL_TIMEOUT(semtimedop, 3, syscall_timespec_timeout, syscall_semtimedop_ret),
#endif
#ifdef SYS_sendfile
	SYSCALL(sendfile),
#endif
#ifdef SYS_sendfile64
	SYSCALL(sendfile64),
#endif
#ifdef SYS_sendmmsg
	SYSCALL(sendmmsg),
#endif
#ifdef SYS_sendmsg
	SYSCALL(sendmsg),
#endif
#ifdef SYS_sendto
	SYSCALL(sendto),
#endif
#ifdef SYS_setdomainname
	SYSCALL(setdomainname),
#endif
#ifdef SYS_setfsgid
	SYSCALL(setfsgid),
#endif
#ifdef SYS_setfsgid32
	SYSCALL(setfsgid32),
#endif
#ifdef SYS_setfsuid
	SYSCALL(setfsuid),
#endif
#ifdef SYS_setfsuid32
	SYSCALL(setfsuid32),
#endif
#ifdef SYS_setgid
	SYSCALL(setgid),
#endif
#ifdef SYS_setgid32
	SYSCALL(setgid32),
#endif
#ifdef SYS_setgroups
	SYSCALL(setgroups),
#endif
#ifdef SYS_setgroups32
	SYSCALL(setgroups32),
#endif
#ifdef SYS_sethostname
	SYSCALL(sethostname),
#endif
#ifdef SYS_setitimer
	SYSCALL(setitimer),
#endif
#ifdef SYS_set_mempolicy
	SYSCALL(set_mempolicy),
#endif
#ifdef SYS_setns
	SYSCALL(setns),
#endif
#ifdef SYS_setpgid
	SYSCALL(setpgid),
#endif
#ifdef SYS_setpriority
	SYSCALL(setpriority),
#endif
#ifdef SYS_setregid
	SYSCALL(setregid),
#endif
#ifdef SYS_setregid32
	SYSCALL(setregid32),
#endif
#ifdef SYS_setresgid
	SYSCALL(setresgid),
#endif
#ifdef SYS_setresgid32
	SYSCALL(setresgid32),
#endif
#ifdef SYS_setresuid
	SYSCALL(setresuid),
#endif
#ifdef SYS_setresuid32
	SYSCALL(setresuid32),
#endif
#ifdef SYS_setreuid
	SYSCALL(setreuid),
#endif
#ifdef SYS_setreuid32
	SYSCALL(setreuid32),
#endif
#ifdef SYS_setrlimit
	SYSCALL(setrlimit),
#endif
#ifdef SYS_set_robust_list
	SYSCALL(set_robust_list),
#endif
#ifdef SYS_setsid
	SYSCALL(setsid),
#endif
#ifdef SYS_setsockopt
	SYSCALL(setsockopt),
#endif
#ifdef SYS_set_thread_area
	SYSCALL(set_thread_area),
#endif
#ifdef SYS_set_tid_address
	SYSCALL(set_tid_address),
#endif
#ifdef SYS_settimeofday
	SYSCALL(settimeofday),
#endif
#ifdef SYS_setuid
	SYSCALL(setuid),
#endif
#ifdef SYS_setuid32
	SYSCALL(setuid32),
#endif
#ifdef SYS_setxattr
	SYSCALL(setxattr),
#endif
#ifdef SYS_sgetmask
	SYSCALL(sgetmask),
#endif
#ifdef SYS_shmat
	SYSCALL(shmat),
#endif
#ifdef SYS_shmctl
	SYSCALL(shmctl),
#endif
#ifdef SYS_shmdt
	SYSCALL(shmdt),
#endif
#ifdef SYS_shmget
	SYSCALL(shmget),
#endif
#ifdef SYS_shutdown
	SYSCALL(shutdown),
#endif
#ifdef SYS_sigaction
	SYSCALL(sigaction),
#endif
#ifdef SYS_sigaltstack
	SYSCALL(sigaltstack),
#endif
#ifdef SYS_signal
	SYSCALL(signal),
#endif
#ifdef SYS_signalfd
	SYSCALL(signalfd),
#endif
#ifdef SYS_signalfd4
	SYSCALL(signalfd4),
#endif
#ifdef SYS_sigpending
	SYSCALL(sigpending),
#endif
#ifdef SYS_sigprocmask
	SYSCALL(sigprocmask),
#endif
#ifdef SYS_sigreturn
	SYSCALL(sigreturn),
#endif
#ifdef SYS_sigsuspend
	SYSCALL(sigsuspend),
#endif
#ifdef SYS_socket
	SYSCALL(socket),
#endif
#ifdef SYS_socketcall
	SYSCALL(socketcall),
#endif
#ifdef SYS_socketpair
	SYSCALL(socketpair),
#endif
#ifdef SYS_splice
	SYSCALL(splice),
#endif
#ifdef SYS_ssetmask
	SYSCALL(ssetmask),
#endif
#ifdef SYS_stat
	SYSCALL(stat),
#endif
#ifdef SYS_stat64
	SYSCALL(stat64),
#endif
#ifdef SYS_statfs
	SYSCALL(statfs),
#endif
#ifdef SYS_statfs64
	SYSCALL(statfs64),
#endif
#ifdef SYS_stime
	SYSCALL(stime),
#endif
#ifdef SYS_stty
	SYSCALL(stty),
#endif
#ifdef SYS_swapoff
	SYSCALL(swapoff),
#endif
#ifdef SYS_swapon
	SYSCALL(swapon),
#endif
#ifdef SYS_symlink
	SYSCALL(symlink),
#endif
#ifdef SYS_symlinkat
	SYSCALL(symlinkat),
#endif
#ifdef SYS_sync
	SYSCALL(sync),
#endif
#ifdef SYS_sync_file_range
	SYSCALL(sync_file_range),
#endif
#ifdef SYS_syncfs
	SYSCALL(syncfs),
#endif
#ifdef SYS__sysctl
	SYSCALL(_sysctl),
#endif
#ifdef SYS_sysfs
	SYSCALL(sysfs),
#endif
#ifdef SYS_sysinfo
	SYSCALL(sysinfo),
#endif
#ifdef SYS_syslog
	SYSCALL(syslog),
#endif
#ifdef SYS_tee
	SYSCALL(tee),
#endif
#ifdef SYS_tgkill
	SYSCALL(tgkill),
#endif
#ifdef SYS_time
	SYSCALL(time),
#endif
#ifdef SYS_timer_create
	SYSCALL(timer_create),
#endif
#ifdef SYS_timer_delete
	SYSCALL(timer_delete),
#endif
#ifdef SYS_timerfd_create
	SYSCALL(timerfd_create),
#endif
#ifdef SYS_timerfd_gettime
	SYSCALL(timerfd_gettime),
#endif
#ifdef SYS_timerfd_settime
	SYSCALL(timerfd_settime),
#endif
#ifdef SYS_timer_getoverrun
	SYSCALL(timer_getoverrun),
#endif
#ifdef SYS_timer_gettime
	SYSCALL(timer_gettime),
#endif
#ifdef SYS_timer_settime
	SYSCALL(timer_settime),
#endif
#ifdef SYS_times
	SYSCALL(times),
#endif
#ifdef SYS_tkill
	SYSCALL(tkill),
#endif
#ifdef SYS_truncate
	SYSCALL(truncate),
#endif
#ifdef SYS_truncate64
	SYSCALL(truncate64),
#endif
#ifdef SYS_tuxcall
	SYSCALL(tuxcall),
#endif
#ifdef SYS_ugetrlimit
	SYSCALL(ugetrlimit),
#endif
#ifdef SYS_ulimit
	SYSCALL(ulimit),
#endif
#ifdef SYS_umask
	SYSCALL(umask),
#endif
#ifdef SYS_umount
	SYSCALL(umount),
#endif
#ifdef SYS_umount2
	SYSCALL(umount2),
#endif
#ifdef SYS_uname
	SYSCALL(uname),
#endif
#ifdef SYS_unlink
	SYSCALL(unlink),
#endif
#ifdef SYS_unlinkat
	SYSCALL(unlinkat),
#endif
#ifdef SYS_unshare
	SYSCALL(unshare),
#endif
#ifdef SYS_uselib
	SYSCALL(uselib),
#endif
#ifdef SYS_ustat
	SYSCALL(ustat),
#endif
#ifdef SYS_utime
	SYSCALL(utime),
#endif
#ifdef SYS_utimensat
	SYSCALL(utimensat),
#endif
#ifdef SYS_utimes
	SYSCALL(utimes),
#endif
#ifdef SYS_vfork
	SYSCALL(vfork),
#endif
#ifdef SYS_vhangup
	SYSCALL(vhangup),
#endif
#ifdef SYS_vm86
	SYSCALL(vm86),
#endif
#ifdef SYS_vm86old
	SYSCALL(vm86old),
#endif
#ifdef SYS_vmsplice
	SYSCALL(vmsplice),
#endif
#ifdef SYS_vserver
	SYSCALL(vserver),
#endif
#ifdef SYS_wait4
	SYSCALL(wait4),
#endif
#ifdef SYS_waitid
	SYSCALL(waitid),
#endif
#ifdef SYS_waitpid
	SYSCALL(waitpid),
#endif
#ifdef SYS_write
	SYSCALL_CHKARGS(write, 2, syscall_write_args, NULL),
#endif
#ifdef SYS_writev
	SYSCALL(writev),
#endif
};

size_t syscalls_len = ARRAY_SIZE(syscalls);
