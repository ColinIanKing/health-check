/*
 * Copyright (C) 2013-2016 Canonical, Ltd.
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

int procs_traced = 0;

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/ptrace.h>
#if defined(__arm__)
#include <linux/ptrace.h>
#endif
#if defined(__aarch64__)
#include <asm/ptrace.h>
#include <sys/uio.h>
#include <elf.h>
#endif
#include <sys/wait.h>
#if defined(__x86_64__) || defined(__i386__)
#include <sys/reg.h>
#endif
#include <sys/user.h>
#include <errno.h>
#include <limits.h>
#include <pthread.h>

#include "list.h"
#include "syscall.h"
#include "proc.h"
#include "json.h"
#include "net.h"
#include "mem.h"
#include "cpustat.h"
#include "fnotify.h"
#include "ctxt-switch.h"
#include "health-check.h"
#include "timeval.h"

#ifdef SYSCALL_SUPPORTED

#define HASH_TABLE_SIZE	(1997)		/* Must be prime */
#define ARRAY_SIZE(a)	(sizeof(a) / sizeof(a[0]))

#if defined(__aarch64__)
struct arm_pt_regs {
	int regs[18];
};

struct aarch64_regs {
	struct user_pt_regs	usr;
	struct arm_pt_regs	arm;
};
#endif

typedef enum {
	SYSCALL_ENTRY = 0,
	SYSCALL_RETURN,
	SYSCALL_UNKNOWN
} syscall_call_state;

static pthread_t syscall_tracer;
static long int syscall_count = 0;
static int info_emit = false;
static pid_t main_pid = -1;

static syscall_context_t *syscall_get_context(pid_t pid);

static list_t syscall_wakelocks;
static list_t syscall_contexts;		/* This links all the items in syscall_contexts_cache */
static list_t syscall_syncs;
static list_t *__pids;	/* We need to fix this into a global pids cache/list */

/* hash table for syscalls, hashed on pid and syscall number */
static syscall_info_t *syscall_info[HASH_TABLE_SIZE];

/* hash table for cached fds, hashed on pid and fd */
static fd_cache_t *fd_cache[HASH_TABLE_SIZE];

/* hash table for cached filenames, hashed on pid and filename */
static filename_info_t *filename_cache[HASH_TABLE_SIZE];

/* hash table for cached context info, hased on pid */
static syscall_context_t *syscall_contexts_cache[HASH_TABLE_SIZE];

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
 *  syscall_connect_args()
 *	stub for connect syscalls.
 *	A smart approach is to inspect the connect and
 *	see what address is being connected to for the net_*
 *	connections.
 */
static void syscall_connect_args(
	const syscall_t *sc,
	const syscall_info_t *s,
	const pid_t pid)
{
	(void)sc;
	(void)s;
	(void)pid;

	/* Inspect connect address, update network stats */
}

/*
 *  syscall_connect_ret()
 *	trigger a network connection update once a
 *	connect syscall has occurred.
 */
static void syscall_connect_ret(const syscall_t *sc, const syscall_info_t *s, const int ret)
{
	(void)sc;
	(void)ret;

	(void)net_connection_pid(s->proc->pid);
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

			if ((j_nanosleep_error= j_obj_new_obj()) == NULL)
				return;
			j_obj_array_add(j_obj, j_nanosleep_error);
			if ((j_error = j_obj_new_obj()) == NULL)
				return;
			j_obj_obj_add(j_nanosleep_error, "nanosleep-error", j_error);
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

		if ((j_timeout = j_obj_new_obj()) == NULL)
			return;
		j_obj_array_add(j_obj, j_timeout);
		if ((j_poll = j_obj_new_obj()) == NULL)
			return;
		j_obj_obj_add(j_timeout, "polling-timeout", j_poll);
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
/*
 *  syscall_semtimedop_ret()
 *	handler for return for semtimedop syscall
 */
static void syscall_semtimedop_ret(json_object *j_obj, const syscall_t *sc, const syscall_info_t *s)
{
	(void)j_obj,
	(void)sc;
	(void)s;
	/* No-op for now, need to examine errno */
}
#endif

#if defined(SYS_mq_timedreceive)
/*
 *  syscall_mq_timedreceive_ret()
 *	handler for return for mq_timedreceive syscall
 */
static void syscall_mq_timedreceive_ret(json_object *j_obj, const syscall_t *sc, const syscall_info_t *s)
{
	(void)j_obj,
	(void)sc;
	(void)s;
	/* No-op for now, need to examine errno */
}
#endif

#if defined(SYS_mq_timedsend)
/*
 *  syscall_mq_timedsend_ret()
 *	handler for return for mq_timedsend syscall
 */
static void syscall_mq_timedsend_ret(json_object *j_obj, const syscall_t *sc, const syscall_info_t *s)
{
	(void)j_obj,
	(void)sc;
	(void)s;
	/* No-op for now, need to examine errno */
}
#endif

/*
 *  syscall_get_call_state()
 *	are we entering a system call or exiting it or don't know?
 */
static inline syscall_call_state syscall_get_call_state(const pid_t pid)
{
#if defined(__x86_64__)
	errno = 0;
	if (ptrace(PTRACE_PEEKUSER, pid, sizeof(long) * RAX, NULL) != -ENOSYS)
		return SYSCALL_RETURN;
	if (errno)
		return SYSCALL_UNKNOWN;
	return SYSCALL_ENTRY;

#elif defined(__i386__)
	errno = 0;
	if (ptrace(PTRACE_PEEKUSER, pid, sizeof(long) * EAX, NULL) != -ENOSYS)
		return SYSCALL_RETURN;
	if (errno)
		return SYSCALL_UNKNOWN;
	return SYSCALL_ENTRY;

#elif defined(__arm__) || defined(__aarch64__) || defined (__powerpc__)
	(void)pid;

	return SYSCALL_UNKNOWN;	/* Don't think it is possible to do this */
#else
	(void)pid;

	return SYSCALL_UNKNOWN;
#endif
}


/*
 *  syscall_get_call()
 *	get syscall number
 */
static inline int syscall_get_call(const pid_t pid, int *syscall)
{
#if defined(__x86_64__)
	errno = 0;
	*syscall = ptrace(PTRACE_PEEKUSER, pid, sizeof(long) * ORIG_RAX, NULL);
	if (errno) {
		*syscall = -1;
		return -1;
	}
	return 0;
#elif defined(__i386__)
	errno = 0;
	*syscall = ptrace(PTRACE_PEEKUSER, pid, sizeof(long) * ORIG_EAX, NULL);
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
			fprintf(stderr, "bad syscall trap 0x%lx.\n", sc);
			*syscall = -1;
			return -1;
		}
		sc &= 0xfffff;
	}

	if (sc & 0x0f0000)
		sc &= 0xffff;

	*syscall = sc;
	return 0;
#elif defined(__powerpc__)
	errno = 0;
	*syscall = ptrace(PTRACE_PEEKUSER, pid, sizeof(long) * PT_R0, NULL);
	if (errno) {
		*syscall = -1;
		return -1;
	}
	return 0;
#elif defined (__aarch64__)
	struct aarch64_regs regs;
	struct iovec io = {
		.iov_base = &regs
	};

	errno = 0;
	io.iov_len = sizeof(struct aarch64_regs);
	ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &io);
	if (errno)
		return -1;

	switch (io.iov_len) {
	case sizeof(regs.arm):
		*syscall = regs.arm.regs[7];
		break;
	case sizeof(regs.usr):
		*syscall = regs.usr.regs[8];
		break;
	default:
		*syscall = 0;
		return -1;
	}
	return 0;
#else
#warning syscall_get_call not implemented for this arch
	(void)pid;

	*syscall = -1;
	return -1;
#endif
}

/*
 *  syscall_get_return()
 *	get syscall return code
 */
static inline int syscall_get_return(const pid_t pid, int *rc)
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
#elif defined (__aarch64__)
	struct aarch64_regs regs;
	struct iovec io = {
		.iov_base = &regs
	};

	errno = 0;
	io.iov_len = sizeof(struct aarch64_regs);
	ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &io);
	if (errno)
		return -1;

	*rc = regs.usr.regs[0];
	return 0;
#elif defined(__powerpc__)
	long flag;

	errno = 0;
	flag = ptrace(PTRACE_PEEKUSER, pid, sizeof(long) * PT_CCR, NULL);
	if (errno)
		return -1;
	*rc = ptrace(PTRACE_PEEKUSER, pid, sizeof(long) * PT_R3, NULL);
	if (errno)
		return -1;
	if (flag & 0x10000000)
		*rc = -(*rc);
	return 0;
#else
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
	memset(args, 0, sizeof(args[0]) * arg);

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
		fprintf(stderr, "Unknown personality, CS=0x%x.\n", (int)cs);
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
#elif defined (__aarch64__)
	struct aarch64_regs regs;
	struct iovec io = {
		.iov_base = &regs
	};
	int i;

	errno = 0;
	io.iov_len = sizeof(struct aarch64_regs);
	ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &io);
	if (errno)
		return -1;

	for (i = 0; i <= arg; i++)
		args[i] = regs.usr.regs[i];

	return 0;
#elif defined (__powerpc__)
	int i;

	for (i = 0; i <= arg; i++) {
		int reg = (i == 0) ? PT_ORIG_R3 : (PT_R3 + i);

		errno = 0;
		args[i] = ptrace(PTRACE_PEEKUSER, pid, reg * sizeof(unsigned long), NULL);
		if (errno)
			return -1;
	}
	return 0;
#else
	int i;

	for (i = 0; i <= arg; i++)
		args[i] = 0;

	fprintf(stderr, "Unknown arch.\n");
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
 *  hash_filename()
 *	hash pid and filename, from Dan Bernstein comp.lang.c (xor version)
 */
static uint32_t hash_filename(const pid_t pid, const char *filename)
{
	register uint32_t hash = 5381 ^ pid;
	register int c;
	register const char *str = filename;

	while ((c = *str++)) {
		/* (hash * 33) ^ c */
		hash = ((hash << 5) + hash) ^ c;
	}
	return hash % HASH_TABLE_SIZE;
}

/*
 *  hash_syscall_context
 *	hash by pid
 */
static inline unsigned long hash_syscall_context(const pid_t pid)
{
	unsigned long h = (unsigned long)pid;

	return h % HASH_TABLE_SIZE;
}

/*
 *  syscall_count_cmp()
 *	syscall usage count sort comparitor
 */
static int syscall_count_cmp(const void *data1, const void *data2)
{
	syscall_info_t *s1 = (syscall_info_t *)data1;
	syscall_info_t *s2 = (syscall_info_t *)data2;

	if (s1->proc->pid == s2->proc->pid)
		return s2->count - s1->count;
	else
		return s1->proc->pid - s2->proc->pid;
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
			list_free(&s->return_history, free);
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
	uint64_t total, usecs_total = 0;
#ifndef JSON_OUTPUT
	(void)j_tests;
#endif

	if (opt_flags & OPT_BRIEF)
		return;

	list_init(&sorted);

	for (i = 0; i < HASH_TABLE_SIZE; i++) {
		syscall_info_t *s;

		for (s = syscall_info[i]; s; s = s->next) {
			if (list_add_ordered(&sorted, s, syscall_count_cmp) == NULL)
				goto out;
			usecs_total += s->usecs_total;
		}
	}

	printf("System calls traced:\n");
	printf("  PID  Process              Syscall               Count    Rate/Sec    Total μSecs  %% Call Time\n");
	for (total = 0, l = sorted.head; l; l = l->next) {
		char name[64];
		syscall_info_t *s = (syscall_info_t *)l->data;

		syscall_name(s->syscall, name, sizeof(name));
		printf(" %5i %-20.20s %-20.20s %6" PRIu64 " %12.4f %13" PRIu64 "    %8.4f\n",
			s->proc->pid, s->proc->cmdline, name, s->count,
			(double)s->count / duration, s->usecs_total,
			(double)s->usecs_total * 100.0 / (double)usecs_total);
		count++;
		total += s->count;
	}
	if (count > 1) {
		printf(" %-46.46s%8" PRIu64 " %12.4f %13" PRIu64 "\n", "Total",
			total, (double)total / duration, usecs_total);
	}
	printf("\n");

#ifdef JSON_OUTPUT
	if (j_tests) {
		json_object *j_syscall, *j_syscall_infos, *j_syscall_info;

		if ((j_syscall = j_obj_new_obj()) == NULL)
			goto out;
		j_obj_obj_add(j_tests, "system-calls", j_syscall);
		if ((j_syscall_infos = j_obj_new_array()) == NULL)
			goto out;
                j_obj_obj_add(j_syscall, "system-calls-per-process", j_syscall_infos);
		for (total = 0, l = sorted.head; l; l = l->next) {
			char name[64];
			syscall_info_t *s = (syscall_info_t *)l->data;

			syscall_name(s->syscall, name, sizeof(name));
			if ((j_syscall_info = j_obj_new_obj()) == NULL)
				goto out;
			j_obj_new_int32_add(j_syscall_info, "pid", s->proc->pid);
			j_obj_new_int32_add(j_syscall_info, "ppid", s->proc->ppid);
			j_obj_new_int32_add(j_syscall_info, "is-thread", s->proc->is_thread);
			j_obj_new_string_add(j_syscall_info, "name", s->proc->cmdline);
			j_obj_new_string_add(j_syscall_info, "system-call", name);
			j_obj_new_int64_add(j_syscall_info, "system-call-count", s->count);
			j_obj_new_double_add(j_syscall_info, "system-call-rate",
				(double)s->count / duration);
			j_obj_new_int64_add(j_syscall_info, "system-call-total-microseconds", s->usecs_total);
			j_obj_array_add(j_syscall_infos, j_syscall_info);
			total += s->count;
		}
		if ((j_syscall_info = j_obj_new_obj()) == NULL)
			goto out;
		j_obj_obj_add(j_syscall, "system-calls-total", j_syscall_info);
		j_obj_new_int64_add(j_syscall_info, "system-call-count-total", total);
		j_obj_new_double_add(j_syscall_info, "system-call-count-total-rate",
			(double)total / duration);
	}
#endif

out:
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

#if defined(SYS__newselect) || defined(SYS_select)
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
#endif


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
#if defined(SYS_write) && defined(SYS_close)
static void *syscall_peek_data(const pid_t pid, const unsigned long addr, const size_t len)
{
	unsigned long *data;
	size_t i, n = (len + sizeof(unsigned long) - 1) / sizeof(unsigned long);

	if ((data = calloc(sizeof(unsigned long), n + 1)) == NULL) {
		health_check_out_of_memory("allocating syscall peek buffer");
		return NULL;
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
 *  syscall_fd_cache_lookup()
 *	lookup a fd cache item based on the pid and file descriptor
 *	if it does not exist, create a new entry. if it was previously
 *	closed re-load the cache item for this fd.
 */
static fd_cache_t *syscall_fd_cache_lookup(const pid_t pid, const int fd)
{
	fd_cache_t *fc;
	unsigned long h = hash_fd(pid, fd);

	for (fc = fd_cache[h]; fc; fc = fc->next) {
		if (fc->pid == pid && fc->fd == fd)
			break;
	}
	if (fc == NULL) {
		if ((fc = calloc(1, sizeof(*fc))) == NULL) {
			health_check_out_of_memory("allocating file descriptor cache item");
			return NULL;
		}
		fc->pid = pid;
		fc->fd = fd;
		fc->filename = fnotify_get_filename(pid, fd);
		if (fc->filename == NULL) {
			health_check_out_of_memory("allocating filename");
			free(fc);
			return NULL;
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
				health_check_out_of_memory("allocating filename");
				free(fc);
				return NULL;
			}
		}
		pthread_mutex_unlock(&fc->mutex);
	}

	return fc;
}


/*
 *  syscall_close_args()
 *	keep track of wakelock closes
 */
static void syscall_close_args(
	const syscall_t *sc,
	const syscall_info_t *s,
	const pid_t pid)
{
	unsigned long args[sc->arg + 1];
	fd_cache_t *fc;
	unsigned long h;
	int fd;

	(void)s;

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
	const syscall_info_t *s,
	const pid_t pid)
{
	unsigned long args[sc->arg + 1];
	fd_cache_t *fc;
	int fd;

	if (!(opt_flags & OPT_WAKELOCKS_HEAVY))
		return;

	(void)s;

	syscall_get_args(pid, sc->arg, args);
	fd = (int)args[0];
	if ((fc = syscall_fd_cache_lookup(pid, fd)) == NULL)
		return;

	pthread_mutex_lock(&fc->mutex);
	if (!strcmp(fc->filename, "/sys/power/wake_lock") ||
	    !strcmp(fc->filename, "/sys/power/wake_unlock")) {
		unsigned long addr = args[1];
		size_t count = (size_t)args[2];
		char *lockname;
		syscall_wakelock_info_t *info;

		if ((lockname = syscall_peek_data(pid, addr, count)) == NULL) {
			pthread_mutex_unlock(&fc->mutex);
			return;
		}
		if ((info = calloc(1, sizeof(*info))) == NULL) {
			health_check_out_of_memory("allocating wakelock information");
			pthread_mutex_unlock(&fc->mutex);
			free(lockname);
			return;
		}

		info->pid = pid;
		info->lockname = lockname;
		info->locked = strcmp(fc->filename, "/sys/power/wake_unlock");
		gettimeofday(&info->tv, NULL);

		if (list_append(&syscall_wakelocks, info) == NULL) {
			free(info);
		}
	}
	pthread_mutex_unlock(&fc->mutex);
}
#endif

#ifdef SYS_exit
/*
 *  syscall_exit_args()
 *	keep track of exit calls
 */
static void syscall_exit_args(
	const syscall_t *sc,
	const syscall_info_t *s,
	const pid_t pid)
{
	(void)s;
	(void)sc;

	/*
	 *  Before we exit we need to gather the
	 *  final accounting stats for the process
	 */
	proc_info_t *proc = proc_cache_find_by_pid(pid);
	if (proc) {
		(void)cpustat_get_by_proc(proc, PROC_FINISH);
		(void)ctxt_switch_get_by_proc(proc, PROC_FINISH);
		(void)mem_get_by_proc(proc, PROC_FINISH);
	}
}
#endif

#if defined(SYS_fsync) || defined(SYS_fdatasync) || defined(SYS_syncfs) || defined(SYS_sync)
/*
 *  syscall_sync_info_find_by_pid()
 *	local sync accounting related data from pid
 */
static syscall_sync_info_t *syscall_sync_info_find_by_pid(const pid_t pid)
{
	link_t *l;
	syscall_sync_info_t *info;

	for (l = syscall_syncs.head; l; l = l->next) {
		info = (syscall_sync_info_t *)l->data;
		if (info->pid == pid)
			return info;
	}

	if ((info = calloc(1, sizeof(*info))) == NULL) {
		health_check_out_of_memory("allocating file sync accounting info");
		return NULL;
	}

	info->pid = pid;
	if (list_append(&syscall_syncs, info) == NULL) {
		free(info);
		return NULL;
	}

	return info;
}
#endif

#if defined(SYS_fsync) || defined(SYS_fdatasync) || defined(SYS_syncfs) || defined(SYS_sync_file_range)
/*
 *  syscall_account_sync_file()
 *	accounting for fsync, fdatasync and syncfs system calls
 */
static void syscall_account_sync_file(syscall_sync_info_t *info, const int syscall, const int pid, const int fd)
{
	syscall_sync_file_t *f;
	fd_cache_t *fc;
	link_t *l;

	if ((fc = syscall_fd_cache_lookup(pid, fd)) == NULL)
		return;

	for (l = info->sync_file.head; l; l = l->next) {
		f = (syscall_sync_file_t *)l->data;
		if ((f->syscall == syscall) && !strcmp(f->filename, fc->filename)) {
			f->count++;
			return;
		}
	}

	if ((f = calloc(1, sizeof(*f))) == NULL) {
		health_check_out_of_memory("allocating file sync filename info");
		return;
	}

	f->filename = strdup(fc->filename);
	f->syscall = syscall;
	f->count = 1;

	if (list_append(&info->sync_file, f) == NULL) {
		free(f->filename);
		free(f);
	}
}

/*
 *  syscall_fsync_generic_args()
 *	keep track of fsync, fdatasync and syncfs calls
 */
static void syscall_fsync_generic_args(
	const syscall_t *sc,
	const syscall_info_t *s,
	const pid_t pid)
{
	unsigned long args[sc->arg + 1];
	syscall_sync_info_t *info;

	(void)s;

	syscall_get_args(pid, sc->arg, args);
	if ((info = syscall_sync_info_find_by_pid(pid)) == NULL)
		return;
	info->fsync_count++;
	info->total_count++;
	syscall_account_sync_file(info, sc->syscall, pid, (int)args[0]);
}
#endif

#ifdef SYS_sync
/*
 *  syscall_sync_args()
 *	keep track of sync calls
 */
static void syscall_sync_args(
	const syscall_t *sc,
	const syscall_info_t *s,
	const pid_t pid)
{
	syscall_sync_info_t *info;

	(void)sc;
	(void)s;

	if ((info = syscall_sync_info_find_by_pid(pid)) == NULL)
		return;
	info->sync_count++;
	info->total_count++;
}
#endif

#ifdef SYS_brk
/*
 *  syscall_account_sync_file()
 *	accounting for brk system call
 */
static void syscall_brk_args(
	const syscall_t *sc,
	const syscall_info_t *s,
	const pid_t pid)
{
	unsigned long args[sc->arg + 1];
	void *addr;

	(void)s;

	syscall_get_args(pid, sc->arg, args);
	addr = (void *)args[0];

	(void)mem_brk_account(pid, addr);
}
#endif

#if defined(SYS_mmap) || defined(SYS_mmap2)
/*
 *  syscall_mmap_args()
 *	accounting for mmap and mmap2 system calls
 */
static void syscall_mmap_args(
	const syscall_t *sc,
	const syscall_info_t *s,
	const pid_t pid)
{
	unsigned long args[sc->arg + 2];

	(void)s;

	syscall_get_args(pid, sc->arg, args);

	(void)mem_mmap_account(pid, (size_t)args[1], true);
}
#endif

#ifdef SYS_munmap
/*
 *  syscall_munmap_args()
 *	accounting for munmap system call
 */
static void syscall_munmap_args(
	const syscall_t *sc,
	const syscall_info_t *s,
	const pid_t pid)
{
	unsigned long args[sc->arg + 2];

	(void)s;

	syscall_get_args(pid, sc->arg, args);

	mem_mmap_account(pid, (size_t)args[1], false);
}
#endif

/*
 *  syscall_sync_cmp()
 *	syscall total usage list sort compare
 */
static int syscall_sync_cmp(const void *d1, const void *d2)
{
	syscall_sync_info_t *s1 = (syscall_sync_info_t *)d1;
	syscall_sync_info_t *s2 = (syscall_sync_info_t *)d2;

	return s2->total_count - s1->total_count;
}

/*
 *  syscall_sync_free_fileinfo()
 *	free sync file accounting info
 */
static void syscall_sync_free_fileinfo(void *data)
{
	syscall_sync_file_t *f = (syscall_sync_file_t *)data;

	free(f->filename);
	free(f);
}

/*
 *  syscall_syncs_free_item()
 *	free sync accounting info
 */
static void syscall_sync_free_item(void *data)
{
	syscall_sync_info_t *info = (syscall_sync_info_t *)data;

	list_free(&info->sync_file, syscall_sync_free_fileinfo);
	free(info);
}

/*
 *  syscall_dump_sync()
 *	dump sync family of syscall usage stats
 */
void syscall_dump_sync(json_object *j_tests, double duration)
{
	list_t sorted;
	link_t *l;
	syscall_sync_info_t *info;
	bool sync_filenames = false;

#if !defined(JSON_OUTPUT)
	(void)j_tests;
#endif

	printf("Filesystem Syncs:\n");

	list_init(&sorted);
	for (l = syscall_syncs.head; l; l = l->next) {
		if (list_add_ordered(&sorted, l->data, syscall_sync_cmp) == NULL)
			goto out;
	}

	if (syscall_syncs.head == NULL) {
		printf(" None.\n\n");
	} else {
		printf("  PID   fdatasync    fsync     sync   syncfs    total   total (Rate)\n");
		for (l = sorted.head; l; l = l->next) {
			info = (syscall_sync_info_t *)l->data;
			printf(" %5i   %8" PRIu64 " %8" PRIu64 " %8" PRIu64 " %8" PRIu64 " %8" PRIu64 " %8.2f\n",
				info->pid,
				info->fdatasync_count, info->fsync_count,
				info->sync_count, info->syncfs_count,
				info->total_count, (double)info->total_count / duration);
				if (info->sync_file.length)
					sync_filenames = true;
		}
		printf("\n");
	}


#ifdef JSON_OUTPUT
	if (j_tests) {
		json_object *j_syscall, *j_syscall_infos, *j_syscall_info;
		uint64_t total_fdatasync = 0, total_fsync = 0, total_sync = 0, total_syncfs = 0;

		if ((j_syscall = j_obj_new_obj()) == NULL)
			goto out;
		j_obj_obj_add(j_tests, "file-system-syncs", j_syscall);
		if ((j_syscall_infos = j_obj_new_array()) == NULL)
			goto out;
                j_obj_obj_add(j_syscall, "sync-system-calls-per-process", j_syscall_infos);
		for (l = sorted.head; l; l = l->next) {
			info = (syscall_sync_info_t *)l->data;
			j_syscall_info = j_obj_new_obj();
			j_obj_new_int32_add(j_syscall_info, "pid", info->pid);
			j_obj_new_int64_add(j_syscall_info, "fdatasync-call-count", info->fdatasync_count);
			j_obj_new_double_add(j_syscall_info, "fdatasync-call-rate", (double)info->fdatasync_count / duration);
			j_obj_new_int64_add(j_syscall_info, "fsync-call-count", info->fsync_count);
			j_obj_new_double_add(j_syscall_info, "fsync-call-rate", (double)info->fsync_count / duration);
			j_obj_new_int64_add(j_syscall_info, "sync-call-count", info->sync_count);
			j_obj_new_double_add(j_syscall_info, "sync-call-rate", (double)info->sync_count / duration);
			j_obj_new_int64_add(j_syscall_info, "syncfs-call-count", info->syncfs_count);
			j_obj_new_double_add(j_syscall_info, "syncfs-call-rate", (double)info->syncfs_count / duration);
			j_obj_array_add(j_syscall_infos, j_syscall_info);

			total_fdatasync += info->fdatasync_count;
			total_fsync += info->fsync_count;
			total_sync += info->sync_count;
			total_syncfs += info->syncfs_count;
		}

		if ((j_syscall_info = j_obj_new_obj()) == NULL)
			goto out;
                j_obj_obj_add(j_syscall, "sync-system-calls-total", j_syscall_info);
		j_obj_new_int64_add(j_syscall_info, "fdatasync-call-count-total", total_fdatasync);
		j_obj_new_double_add(j_syscall_info, "fdatasync-call-count-total-rate", (double)total_fdatasync / duration);
		j_obj_new_int64_add(j_syscall_info, "fsync-call-count-total", total_fsync);
		j_obj_new_double_add(j_syscall_info, "fsync-call-count-total-rate", (double)total_fsync / duration);
		j_obj_new_int64_add(j_syscall_info, "sync-call-count-total", total_sync);
		j_obj_new_double_add(j_syscall_info, "sync-call-count-total-rate", (double)total_sync / duration);
		j_obj_new_int64_add(j_syscall_info, "syncfs-call-count-total", total_syncfs);
		j_obj_new_double_add(j_syscall_info, "syncfs-call-count-total-rate", (double)total_syncfs / duration);
	}
#endif
	if (sync_filenames) {
		printf("Files Sync'd:\n");
		printf("  PID   syscall    # sync's filename\n");
		for (l = sorted.head; l; l = l->next) {
			link_t *ll;
			info = (syscall_sync_info_t *)l->data;

			for (ll = info->sync_file.head; ll; ll = ll->next) {
				char tmp[64];

				syscall_sync_file_t *f = (syscall_sync_file_t *)ll->data;
				syscall_name(f->syscall, tmp, sizeof(tmp));
				printf(" %5i  %-10.10s %8" PRIu64 " %s\n",
					info->pid, tmp, f->count, f->filename);
			}
		}
		printf("\n");
	}
#ifdef JSON_OUTPUT
	if (j_tests) {
		json_object *j_syscall, *j_syscall_infos, *j_syscall_info;
		uint64_t total_files_sync = 0;

		if ((j_syscall = j_obj_new_obj()) == NULL)
			goto out;
		j_obj_obj_add(j_tests, "files-synced", j_syscall);
		if ((j_syscall_infos = j_obj_new_array()) == NULL)
			goto out;
                j_obj_obj_add(j_syscall, "file-sync-per-process", j_syscall_infos);
		for (l = sorted.head; l; l = l->next) {
			link_t *ll;
			info = (syscall_sync_info_t *)l->data;

			for (ll = info->sync_file.head; ll; ll = ll->next) {
				info = (syscall_sync_info_t *)l->data;
				char tmp[64];

				syscall_sync_file_t *f = (syscall_sync_file_t *)ll->data;
				syscall_name(f->syscall, tmp, sizeof(tmp));

				j_syscall_info = j_obj_new_obj();
				j_obj_new_int32_add(j_syscall_info, "pid", info->pid);
				j_obj_new_string_add(j_syscall_info, "syscall", tmp);
				j_obj_new_int64_add(j_syscall_info, "call-count", f->count);
				j_obj_new_double_add(j_syscall_info, "call-rate", (double)f->count / duration);
				j_obj_new_string_add(j_syscall_info, "filename", f->filename);
				j_obj_array_add(j_syscall_infos, j_syscall_info);

				total_files_sync += f->count;
			}
		}
		if ((j_syscall_info = j_obj_new_obj()) == NULL)
			goto out;
                j_obj_obj_add(j_syscall, "files-synced-total", j_syscall_info);
		j_obj_new_int64_add(j_syscall_info, "files-synced-total", total_files_sync);
		j_obj_new_double_add(j_syscall_info, "files-synced-total-rate", (double)total_files_sync / duration);
	}
#endif

out:
	list_free(&sorted, NULL);
}

#ifdef SYS_sendto
/*
 *  syscall_sendto_ret()
 *	keep track of sendto returns
 */
static void syscall_sendto_ret(
	const syscall_t *sc,
	const syscall_info_t *s,
	const int ret)
{
	unsigned long args[sc->arg + 1];
	int sockfd;
	pid_t pid = s->proc->pid;

	syscall_get_args(pid, sc->arg, args);
	sockfd = (int)args[0];

	if (ret >= 0)
		net_account_send(pid, sockfd, (size_t)ret);
}
#endif

#ifdef SYS_recvfrom
/*
 *  syscall_recvfrom_ret()
 *	keep track of recvfrom returns
 */
static void syscall_recvfrom_ret(
	const syscall_t *sc,
	const syscall_info_t *s,
	const int ret)
{
	unsigned long args[sc->arg + 1];
	int sockfd;
	pid_t pid = s->proc->pid;

	syscall_get_args(pid, sc->arg, args);
	sockfd = (int)args[0];

	if (ret >= 0)
		net_account_recv(pid, sockfd, (size_t)ret);
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


/*
 *  syscall_wakelock_names_by_pid()
 *	update wakelock_names list for a new wakelock for a given pid
 */
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
				(void)list_add_ordered(wakelock_names, info->lockname, syscall_wakelock_cmp);
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
#ifdef JSON_OUTPUT
	json_object *j_wakelock_test = NULL, *j_wakelock_infos = NULL, *j_wakelock_info;
#endif

	(void)j_tests;

	if (!(opt_flags & OPT_WAKELOCKS_HEAVY))
		return;

#ifdef JSON_OUTPUT
	if (j_tests) {
		if ((j_wakelock_test = j_obj_new_obj()) == NULL)
			goto out;
		j_obj_obj_add(j_tests, "wakelock-operations-heavy", j_wakelock_test);
		if ((j_wakelock_infos = j_obj_new_array()) == NULL)
			goto out;
		j_obj_obj_add(j_wakelock_test, "wakelock-operations-heavy-per-process", j_wakelock_infos);
	}
#endif

	printf("Wakelock operations by wakelock:\n");
	if (!syscall_wakelocks.head) {
		printf(" None.\n\n");
	} else {
		double total_locked_duration = 0.0;

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
#ifdef JSON_OUTPUT
				if (j_tests) {
					if ((j_wakelock_info = j_obj_new_obj()) == NULL)
						goto out;
					j_obj_new_int32_add(j_wakelock_info, "pid", p->pid);
					j_obj_new_int32_add(j_wakelock_info, "ppid", p->ppid);
					j_obj_new_int32_add(j_wakelock_info, "is-thread", p->is_thread);
					j_obj_new_string_add(j_wakelock_info, "name", p->cmdline);
					j_obj_new_string_add(j_wakelock_info, "lockname", lockname);
					j_obj_new_int64_add(j_wakelock_info, "wakelock-locked", locked);
					j_obj_new_double_add(j_wakelock_info, "wakelock-locked-rate", (double)locked / duration);
					j_obj_new_int64_add(j_wakelock_info, "wakelock-unlocked", unlocked);
					j_obj_new_double_add(j_wakelock_info, "wakelock-unlocked-rate", (double)unlocked / duration);
					j_obj_new_double_add(j_wakelock_info, "wakelock-locked-duration",
						count ? locked_duration / count : 0.0);
					j_obj_array_add(j_wakelock_infos, j_wakelock_info);
				}
#endif
			}
			list_free(&wakelock_names, NULL);
		}
		printf(" Total%40s%8" PRIu64 " %8" PRIu64 " %8.2f %8.2f %12.5f\n", "",
			total_locked, total_unlocked,
			(double)total_locked / duration, (double)total_unlocked / duration,
			total_count ? total_locked_duration / total_count : 0.0);
		printf("\n");
	}
#ifdef JSON_OUTPUT
	if (j_tests) {
		if ((j_wakelock_info = j_obj_new_obj()) == NULL)
				goto out;
			j_obj_obj_add(j_wakelock_test, "wakelock-operations-heavy-total", j_wakelock_info);
			j_obj_new_int64_add(j_wakelock_info, "wakelock-locked-total", total_locked);
			j_obj_new_double_add(j_wakelock_info, "wakelock-locked-total-rate", (double)total_locked / duration);
					j_obj_new_int64_add(j_wakelock_info, "wakelock-unlocked-total", total_unlocked);
			j_obj_new_double_add(j_wakelock_info, "wakelock-unlocked-total-rate", (double)total_unlocked / duration);
	}
out:
#endif

	if (syscall_wakelocks.head && opt_flags & OPT_VERBOSE) {
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

#if defined(SYS_inotify_add_watch) || defined(SYS_execve)
/*
 *  syscall_peek_filename()
 *	get a filename as pointed to by addr
 */
static char *syscall_peek_filename(const pid_t pid, const unsigned long addr)
{
	char *data;
	size_t i, n = 0;
	unsigned long v;

	/* Find how long it is */
	do {
		v = ptrace(PTRACE_PEEKDATA, pid,
			addr + n, NULL) & 0xff;
		n++;
	} while (v);

	if ((data = calloc(sizeof(char), n)) == NULL) {
		health_check_out_of_memory("allocating syscall peek buffer");
		return NULL;
	}

	for (i = 0; i < n; i++)
		data[i] = ptrace(PTRACE_PEEKDATA, pid,
				addr + i, NULL);

	return data;
}

/*
 *  syscall_add_filename()
 *	Add filename into filename cache
 */
void syscall_add_filename(const int syscall, const pid_t pid, const char *filename)
{
	unsigned long h;
	filename_info_t *info;

	if (filename == NULL)
		return;

	h = hash_filename(pid, filename);
	info = filename_cache[h];

	while (info) {
		if (info->pid == pid && !strcmp(info->filename, filename))
			break;
		info = info->next;
	}

	if (!info) {
		info = calloc(1, sizeof(*info));
		if (!info)
			return;
		info->filename = strdup(filename);
		if (!info->filename) {
			free(info);
			return;
		}
		info->syscall = syscall;
		info->pid = pid;
		info->proc = proc_cache_find_by_pid(pid);
		info->count = 1;
		info->next = filename_cache[h];
		filename_cache[h] = info;
	} else {
		info->count++;
	}
}

/*
 *  syscall_filename_cmp()
 *	filename and pid compare
 */
static int syscall_filename_cmp(const void *d1, const void *d2)
{
	filename_info_t *f1 = (filename_info_t *)d1;
	filename_info_t *f2 = (filename_info_t *)d2;

	return f2->count - f1->count;
}

/*
 *  syscall_filename_cache_free()
 *	free up filename cache
 */
static void syscall_filename_cache_free(void)
{
	int i;

	for (i = 0; i < HASH_TABLE_SIZE; i++) {
		filename_info_t *next, *info = filename_cache[i];

		while (info) {
			next = info->next;
			free(info->filename);
			free(info);
			info = next;
		}
	}
}

/*
 *  syscall_dump_filename()
 *	dump filename usage by syscall
 */
void syscall_dump_filename(const char *label, const int syscall, json_object *j_obj, double duration)
{
	int i;
	list_t sorted;
	link_t *l;

	list_init(&sorted);

	for (i = 0; i < HASH_TABLE_SIZE; i++) {
		filename_info_t *info;

		for (info = filename_cache[i]; info; info = info->next) {
			if (info->syscall == syscall) {
				if (list_add_ordered(&sorted, info, syscall_filename_cmp) == NULL)
					goto out;
			}
		}
	}

	if (sorted.length == 0) {
		printf(" None.\n\n");
	} else {
		printf("  PID  Process              Rate/Sec File\n");
		for (l = sorted.head; l; l = l->next) {
			filename_info_t *info = (filename_info_t *)l->data;
			printf(" %5i %-20.20s %8.3f %s\n", info->pid,
				info->proc->cmdline,
				(double)info->count / duration, info->filename);
		}
		printf("\n");
	}
#ifdef JSON_OUTPUT
	if (j_obj) {
		json_object *j_syscall, *j_syscall_infos, *j_syscall_info;

		if ((j_syscall = j_obj_new_obj()) == NULL)
			goto out;
		j_obj_obj_add(j_obj, label, j_syscall);
		if ((j_syscall_infos = j_obj_new_array()) == NULL)
			goto out;
                j_obj_obj_add(j_syscall, "files", j_syscall_infos);
		for (l = sorted.head; l; l = l->next) {
			filename_info_t *info = (filename_info_t *)l->data;

			j_syscall_info = j_obj_new_obj();
			j_obj_new_int32_add(j_syscall_info, "pid", info->pid);
			j_obj_new_int32_add(j_syscall_info, "ppid", info->proc->ppid);
			j_obj_new_int32_add(j_syscall_info, "is_thread", info->proc->is_thread);
			j_obj_new_string_add(j_syscall_info, "name", info->proc->cmdline);
			j_obj_new_int64_add(j_syscall_info, "count", info->count);
			j_obj_new_double_add(j_syscall_info, "access-rate", (double)info->count / duration);
			j_obj_new_string_add(j_syscall_info, "filename", info->filename);
			j_obj_array_add(j_syscall_infos, j_syscall_info);
		}
	}
#endif
	list_free(&sorted, NULL);
out:
	return;
}

#endif

#ifdef SYS_inotify_add_watch
/*
 *  syscall_inotify_add_watch_args()
 *	trace filenames used by inotify_add_watch()
 */
void syscall_inotify_add_watch_args(
	const syscall_t *sc,
	const syscall_info_t *s,
	const pid_t pid)
{
	unsigned long args[sc->arg + 1];
	char *filename;

	(void)s;
	syscall_get_args(pid, sc->arg, args);
	filename = syscall_peek_filename(pid, args[1]);
	if (filename) {
		syscall_add_filename(sc->syscall, pid, filename);
		free(filename);
	}
}

void syscall_dump_inotify(json_object *j_obj, double duration)
{
	printf("Inotify watches added:\n");
	syscall_dump_filename("inotify-watches-added", SYS_inotify_add_watch, j_obj, duration);
}
#else
void syscall_dump_inotify(json_object *j_obj, double duration)
{
	(void)duration;
	(void)j_obj;
}
#endif

#ifdef SYS_execve
/*
 *  syscall_execve_args()
 *	trace filenames used by execve()
 */
void syscall_execve_args(
	const syscall_t *sc,
	const syscall_info_t *s,
	const pid_t pid)
{
	unsigned long args[sc->arg + 1];
	char *filename;

	(void)s;
	syscall_get_args(pid, sc->arg, args);
	filename = syscall_peek_filename(pid, args[0]);
	if (filename) {
		syscall_add_filename(sc->syscall, pid, filename);
		free(filename);
	}
}

void syscall_dump_execve(json_object *j_obj, double duration)
{
	(void)duration;
	(void)j_obj;
	/*
	 * Not 100% reliable yet, so disable this for the moment
	 *
	printf("Programs exec'd:\n");
	syscall_dump_filename("execed-programs", SYS_execve, j_obj, duration);
	*/
}
#else
void syscall_dump_execve(double duration)
{
	(void)duration;
	(void)j_obj;
}
#endif

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
	json_object *j_pollers = NULL;

#if !defined(JSON_OUTPUT)
	(void)j_tests;
#endif

	list_init(&sorted);

	for (i = 0; i < HASH_TABLE_SIZE; i++) {
		syscall_info_t *s;

		for (s = syscall_info[i]; s; s = s->next) {
			int syscall = s->syscall;
			if (syscalls[syscall].call_enter_timeout) {
				if (list_add_ordered(&sorted, s, syscall_count_cmp) == NULL)
					goto out;
				break;
			}
		}
	}

#ifdef JSON_OUTPUT
	uint64_t poll_infinite = 0, poll_zero = 0, count = 0;
	json_object *j_poll_test;
	char tmp[64];

	if (j_tests) {
		json_object *j_syscall, *j_syscall_infos, *j_syscall_info;

		if ((j_syscall = j_obj_new_obj()) == NULL)
			goto out;
		j_obj_obj_add(j_tests, "polling-system-calls", j_syscall);
		if ((j_syscall_infos = j_obj_new_array()) == NULL)
			goto out;
		j_obj_obj_add(j_syscall, "polling-system-calls-per-process", j_syscall_infos);
		for (count = 0, l = sorted.head; l; l = l->next) {
			syscall_info_t *s = (syscall_info_t *)l->data;
			syscall_name(s->syscall, tmp, sizeof(tmp));
			double rate = (double)s->count / duration;
			count += s->count;

			if ((j_syscall_info = j_obj_new_obj()) == NULL)
				goto out;
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
		if ((j_syscall_info = j_obj_new_obj()) == NULL)
			goto out;
		j_obj_obj_add(j_syscall, "polling-system-calls-total", j_syscall_info);
		j_obj_new_int64_add(j_syscall_info, "system-call-count-total", count);
		j_obj_new_double_add(j_syscall_info, "system-call-total-rate", (double)count / duration);
		j_obj_new_int64_add(j_syscall_info, "poll-count-infinite-total", (int64_t)poll_infinite);
		j_obj_new_double_add(j_syscall_info, "poll-count-infinite-total-rate", (double)poll_infinite / duration);
		j_obj_new_int64_add(j_syscall_info, "poll-count-zero-total", poll_zero);
		j_obj_new_double_add(j_syscall_info, "poll-count-zero-total-rate", (double)poll_zero / duration);
	}
#endif

	if (sorted.head) {
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

			printf("\nDistribution of poll timeout times:\n");

			printf("%50.50s", "");
			for (prev = 0.0, bucket = BUCKET_START, i = 0; i < MAX_BUCKET; i++, bucket *= 10.0) {
				(void)syscall_timeout_to_human_time(prev, false, tmp, sizeof(tmp));
				printf(" %6s", i == 0 ? "" : tmp);
				prev = bucket;
			}
			printf("\n");
			printf("%50.50s", "");
			for (i = 0; i < MAX_BUCKET; i++) {
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
			if ((j_poll_test = j_obj_new_obj()) == NULL)
				goto out;
			j_obj_obj_add(j_tests, "polling-system-call-returns", j_poll_test);
			if ((j_pollers = j_obj_new_array()) == NULL)
				goto out;
			j_obj_obj_add(j_poll_test, "polling-system-call-returns-per-process", j_pollers);
		}
#endif
		printf("Polling system call analysis:\n");
		for (l = sorted.head; l; l = l->next) {
			syscall_info_t *s = (syscall_info_t *)l->data;
			if (syscall_valid(s->syscall)) {
				syscall_t *sc = &syscalls[s->syscall];
				if (sc->call_return_timeout)
					sc->call_return_timeout(j_pollers, sc, s);
			}
		}
		if (!info_emit)
			printf(" No bad polling discovered.\n");
		printf("\n");
	}
out:
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
		int ret;

		if (syscall_get_return(pid, &ret) < 0)
			return;

		if (sc->call_return) {
			/* Do call return handling immediately */
			sc->call_return(sc, s, ret);
		} else if (sc->call_return_timeout) {
			/* Collect data and process it at the end of the run */
			syscall_return_info_t *info;
			if ((info = (syscall_return_info_t *)calloc(1, sizeof(*info))) == NULL) {
				health_check_out_of_memory("allocating syscall accounting information");
				return;
			}
			info->timeout = timeout;
			info->ret = ret;

			if (list_append(&s->return_history, info) == NULL)
				free(info);
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
			health_check_out_of_memory("allocating syscall hash item");
			return NULL;
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

	if (++syscall_count >= opt_max_syscalls) {
#if SYSCALL_DEBUG
		printf("HIT SYSCALL LIMIT\n");
#endif
		keep_running = false;
	}

	if (sc->call_enter)
		sc->call_enter(sc, s, pid);
	else if (sc->call_enter_timeout)
		sc->call_enter_timeout(sc, s, pid, *(sc->threshold), timeout);

	return s;
}

/*
 *  syscall_handle_syscall()
 *	system call entry or exit handling
 */
static void syscall_handle_syscall(syscall_context_t *ctxt)
{
	int syscall;
	syscall_call_state state = syscall_get_call_state(ctxt->pid);

	switch (state) {
	case SYSCALL_ENTRY:
		if (syscall_get_call(ctxt->pid, &ctxt->syscall) == -1) {
			ctxt->syscall_info = NULL;
			ctxt->timeout = 0.0;
		} else {
			ctxt->syscall_info = syscall_count_usage(ctxt->pid, ctxt->syscall, &ctxt->timeout);
			if (ctxt->syscall_info)
				gettimeofday(&ctxt->syscall_info->usec_enter, NULL);
		}
		return;

	default:
		/* We don't know what it was, so try and figure it out */
		if (syscall_get_call(ctxt->pid, &syscall) == -1) {
			printf("syscall give up\n");
			/* Not good, abort stats */
			ctxt->syscall_info = NULL;
			ctxt->timeout = 0.0;
			return;
		}
		if (syscall != ctxt->syscall) {
			/* syscall is different, so can't be a return, must be a new syscall */
			ctxt->syscall = syscall;
			ctxt->syscall_info = syscall_count_usage(ctxt->pid, ctxt->syscall, &ctxt->timeout);
			if (ctxt->syscall_info)
				gettimeofday(&ctxt->syscall_info->usec_enter, NULL);
			return;
		}
		/* assume it is a return, but it may not be, fall through to SYSCALL_RETURN.. */

	case SYSCALL_RETURN:
		if (ctxt->syscall_info != NULL) {
			struct timeval t;
			uint64_t usec;

			gettimeofday(&ctxt->syscall_info->usec_return, NULL);
			t = timeval_sub(&ctxt->syscall_info->usec_return, &ctxt->syscall_info->usec_enter);
			usec = (t.tv_sec * 1000000) + t.tv_usec;
			ctxt->syscall_info->usecs_total += usec;
			syscall_account_return(ctxt->syscall_info, ctxt->pid, ctxt->syscall, ctxt->timeout);
		}
		/* We've got a return, so clear info for next syscall */
		ctxt->syscall = -1;
		ctxt->syscall_info = NULL;
		ctxt->timeout = 0.0;
	}
}

/*
 *  syscall_handle_event()
 *	handle a ptrace event (clone, fork, vfork)
 */
static void syscall_handle_event(syscall_context_t *ctxt, int event)
{
	unsigned long msg;
	pid_t child;
	proc_info_t *p;

#if SYSCALL_DEBUG
	printf("EVENT: %d\n", event);
#endif
	switch (event) {
	case PTRACE_EVENT_CLONE:
	case PTRACE_EVENT_FORK:
	case PTRACE_EVENT_VFORK:
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
			(void)proc_pids_add_proc(__pids, p);
			(void)mem_get_by_proc(p, PROC_START);
			(void)cpustat_get_by_proc(p, PROC_START);
			(void)ctxt_switch_get_by_proc(p, PROC_START);
			(void)syscall_get_context(child);
		}
		(void)net_connection_pid(child);	/* Update net connections on new process */
		break;
	case PTRACE_EVENT_EXIT:
#if SYSCALL_DEBUG
		printf("PID %d exited\n", ctxt->pid);
#endif
		if (ctxt->state & SYSCALL_CTX_ATTACHED)
			ptrace(PTRACE_CONT, ctxt->pid, 0, 0);
		break;
	default:
		break;
	}
}

/*
 *  syscall_handle_trap()
 *	handle ptrace trap
 */
static inline void syscall_handle_trap(syscall_context_t *ctxt)
{
	siginfo_t siginfo;

	if (ptrace(PTRACE_GETSIGINFO, ctxt->pid, 0, &siginfo) == -1) {
		fprintf(stderr, "Cannot get signal info on pid %d.\n", ctxt->pid);
		return;
	}

	if (siginfo.si_code == SIGTRAP) {
		syscall_handle_syscall(ctxt);
	} else {
		/* printf("breakpoint on PID %d\n", ctxt->pid); */
	}
}

/*
 *  syscall_handle_stop
 *	handle a ptrace stop
 */
static inline int syscall_handle_stop(syscall_context_t *ctxt, const int status)
{
	int event = status >> 16;
	int sig = WSTOPSIG(status);


	if (sig == SIGTRAP) {
#if SYSCALL_DEBUG
		printf("GOT SIGTRAP, event: %d\n", event);
#endif
		if (event) {
			syscall_handle_event(ctxt, event);
		} else {
			syscall_handle_trap(ctxt);
		}
	} else if (sig == SIGCHLD) {
#if SYSCALL_DEBUG
		printf("GOT SIGCHLD, %d\n", ctxt->pid);
#endif
		//procs_traced--;
	} else if (sig == (SIGTRAP | 0x80)) {
		syscall_handle_syscall(ctxt);
	} else if (sig != SIGSTOP) {
		return sig;
	}
	return 0;
}

/*
 *  syscall_context_find_by_pid()
 * 	find syscall context by pid
 */
static syscall_context_t *syscall_context_find_by_pid(const pid_t pid)
{
	syscall_context_t *ctxt;
	unsigned long h = hash_syscall_context(pid);

	for (ctxt = syscall_contexts_cache[h]; ctxt; ctxt = ctxt->next)
		if (ctxt->pid == pid)
			return ctxt;

	return NULL;
}

/*
 *  syscall_get_context()
 *	each ptraced thread or process has a ptrace state context,
 *	this function looks this up via the pid. If it does not
 *	already exist, create a new context.
 */
static syscall_context_t *syscall_get_context(pid_t pid)
{
	syscall_context_t *ctxt;

	ctxt = syscall_context_find_by_pid(pid);
	if (ctxt == NULL) {
		unsigned long h = hash_syscall_context(pid);
		if ((ctxt = calloc(1, sizeof(*ctxt))) == NULL) {
			fprintf(stderr, "Out of memory allocating tracing context.\n");
			return NULL;
		}
		ctxt->pid = pid;
		ctxt->proc = proc_cache_find_by_pid(pid);
		ctxt->timeout = 0.0;
		ctxt->syscall = -1;
		ctxt->syscall_info = NULL;
		ctxt->state |= SYSCALL_CTX_ALIVE;

		/* Add to fast look up cache and list */
		if (list_append(&syscall_contexts, ctxt) == NULL) {
			free(ctxt);
			return NULL;
		}
		ctxt->next = syscall_contexts_cache[h];
		syscall_contexts_cache[h] = ctxt;
		procs_traced++;
#if SYSCALL_DEBUG
		printf("NEW PROCESS %d, TRACED: %d\n", pid, procs_traced);
#endif
	}
	return ctxt;
}

/*
 *  syscall_trace_cleanup()
 *	clean up tracing
 */
static void syscall_trace_cleanup(void *arg)
{
	link_t *l;

	(void)arg;
	for (l = syscall_contexts.head; l; l = l->next) {
		syscall_context_t *ctxt = (syscall_context_t *)l->data;
		if (ctxt->state & SYSCALL_CTX_ATTACHED) {
			int status;

			kill(ctxt->pid, SIGSTOP);
			waitpid(ctxt->pid, &status, __WALL);
			ptrace(PTRACE_DETACH, ctxt->pid, 0, 0);
			kill(ctxt->pid, SIGCONT);
		}
	}
#if SYSCALL_DEBUG
	printf("SYSCALL TRACE CLEANUP\n");
#endif
	keep_running = false;
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
	unsigned long ptrace_flags;
	static int ret = 0;

	(void)arg;

	pthread_cleanup_push(syscall_trace_cleanup, arg);
	pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);

	ptrace_flags = PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEEXIT;
	if (opt_flags & OPT_FOLLOW_NEW_PROCS) {
		ptrace_flags |= (PTRACE_O_TRACECLONE | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK);
#if SYSCALL_DEBUG
		printf("FOLLOW PROCS\n");
#endif
	}

	for (l = syscall_contexts.head; l; l = l->next) {
		ctxt = (syscall_context_t *)l->data;
		if (ptrace(PTRACE_ATTACH, ctxt->pid, 0, 0) < 0) {
			if (errno == EPERM) {
				fprintf(stderr, "Insufficient privilege to trace process %d\n", ctxt->pid);
			} else {
				fprintf(stderr, "Cannot attach trace to process %d\n", ctxt->pid);
			}
			ret = -1;
			goto done;
		}
		ctxt->state |= SYSCALL_CTX_ATTACHED;
		(void)ptrace(PTRACE_SETOPTIONS, ctxt->pid, 0, ptrace_flags);
	}

#if SYSCALL_DEBUG
	printf("TRACE LOOP\n");
#endif
	while (keep_running && procs_traced > 0) {
		int sig = 0;
		pid_t pid;

		errno = 0;
#if SYSCALL_DEBUG
		printf("WAITPID..\n");
#endif
		if ((pid = waitpid(-1, &status, __WALL)) == -1) {
			if (errno == EINTR || errno == ECHILD) {
#if SYSCALL_DEBUG
				printf("WAITPID returned errno: %d\n", errno);
#endif
				break;
			}
		}

		if ((ctxt = syscall_get_context(pid)) == NULL) {
			fprintf(stderr, "Out of memory allocating tracing context.\n");
			break;
		}

		if (WIFSTOPPED(status)) {
#if SYSCALL_DEBUG
			printf("PROC  %d\n", ctxt->pid);
#endif
			sig = syscall_handle_stop(ctxt, status);
		} else if (WIFEXITED(status)) {
#if SYSCALL_DEBUG
			printf("PROC WIFEXITED %d\n", ctxt->pid);
#endif
			if (ctxt->proc) {
				/*
				 *  We need to probably catch exit in the system call
			 	 *  so we can do accounting, it seems that the proc files
				 *  disappear too early.
				 */
				/*
				(void)cpustat_get_by_proc(ctxt->proc, PROC_FINISH);
				(void)ctxt_switch_get_by_proc(ctxt->proc, PROC_FINISH);
				(void)mem_get_by_proc(ctxt->proc, PROC_FINISH);
				*/
			}
			ctxt->state &= ~(SYSCALL_CTX_ALIVE | SYSCALL_CTX_ATTACHED);
			procs_traced--;
#if SYSCALL_DEBUG
			printf("PROC TRACED: %d\n", procs_traced);
#endif
		}
		else if (WIFSIGNALED(status)) {
			/*
			 *  In an ideal world we could find the final
			 *  stats *before* it died and update CPU stat etc
			 *  TODO: See if we can find out final state before
			 *  signalled.
			 */
#if SYSCALL_DEBUG
			printf("PROC WIGSIGNALED\n");
#endif
			if (WTERMSIG(status) == SIGKILL) {
				/* It died */
				printf("Process %d received SIGKILL during monitoring.\n", pid);
				ctxt->state &= ~(SYSCALL_CTX_ALIVE | SYSCALL_CTX_ATTACHED);
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

#if SYSCALL_DEBUG
	printf("SYSCALL TRACE COMPLETE\n");
#endif
done:
	syscall_trace_cleanup(NULL);
	pthread_cleanup_pop(NULL);
	kill(main_pid, SIGUSR1);
	pthread_exit(&ret);
}

/*
 *  syscall_init()
 *	initialize
 */
void syscall_init(void)
{
	list_init(&syscall_wakelocks);
	list_init(&syscall_contexts);
	list_init(&syscall_syncs);
}

/*
 *  syscall_stop()
 *	stop the ptrace thread
 */
int syscall_stop(void)
{
	int *status = 0;

	pthread_cancel(syscall_tracer);
	pthread_join(syscall_tracer, (void **)&status);

	if (status == PTHREAD_CANCELED)
		return 0;

	return *status;
}

/*
 *  syscall_cleanup()
 *	free up memory
 */
void syscall_cleanup(void)
{
	list_free(&syscall_wakelocks, syscall_wakelock_free);
	list_free(&syscall_contexts, free);
	list_free(&syscall_syncs, syscall_sync_free_item);
	syscall_wakelock_fd_cache_free();
	syscall_hashtable_free();
	syscall_filename_cache_free();
}

/*
 *  syscall_trace_proc()
 *	kick off ptrace thread
 */
int syscall_trace_proc(list_t *pids)
{
	link_t *l;

	__pids = pids;
	main_pid = getpid();

	for (l = pids->head; l; l = l->next) {
		proc_info_t *p = (proc_info_t *)l->data;
		(void)syscall_get_context(p->pid);
	}

	if (pthread_create(&syscall_tracer, NULL, syscall_trace, NULL) < 0) {
		fprintf(stderr, "Failed to create tracing thread.\n");
		return -1;
	}
	return 0;
}

/*
 *  The system call table
 */
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
	SYSCALL_CHK(brk, 0, syscall_brk_args, NULL),
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
	SYSCALL_CHK_TIMEOUT(clock_nanosleep, 2, syscall_timespec_timeout, syscall_nanosleep_generic_ret),
#endif
#ifdef SYS_clock_settime
	SYSCALL(clock_settime),
#endif
#ifdef SYS_clone
	SYSCALL(clone),
#endif
#ifdef SYS_close
	SYSCALL_CHK(close, 0, syscall_close_args, NULL),
#endif
#ifdef SYS_connect
	SYSCALL_CHK(connect, 0, syscall_connect_args, syscall_connect_ret),
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
	SYSCALL_CHK_TIMEOUT(epoll_pwait, 3, syscall_timeout_millisec, syscall_poll_generic_ret),
#endif
#ifdef SYS_epoll_wait
	SYSCALL_CHK_TIMEOUT(epoll_wait, 3, syscall_timeout_millisec, syscall_poll_generic_ret),
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
	SYSCALL_CHK(execve, 0, syscall_execve_args, NULL),
#endif
#ifdef SYS_exit
	SYSCALL_CHK(exit, 0, syscall_exit_args, NULL),
#endif
#ifdef SYS_exit_group
	SYSCALL_CHK(exit_group, 0, syscall_exit_args, NULL),
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
	SYSCALL_CHK(fdatasync, 0, syscall_fsync_generic_args, NULL),
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
	SYSCALL_CHK(fsync, 0, syscall_fsync_generic_args, NULL),
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
	SYSCALL_CHK(inotify_add_watch, 1, syscall_inotify_add_watch_args, NULL),
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
	SYSCALL_CHK(mmap, 1, syscall_mmap_args, NULL),
#endif
#ifdef SYS_mmap2
	SYSCALL_CHK(mmap2, 1, syscall_mmap_args, NULL),
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
	SYSCALL_CHK_TIMEOUT(mq_timedreceive, 4, syscall_timespec_timeout, syscall_mq_timedreceive_ret),
#endif
#ifdef SYS_mq_timedsend
	SYSCALL_CHK_TIMEOUT(mq_timedsend, 4, syscall_timespec_timeout, syscall_mq_timedsend_ret),
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
	SYSCALL_CHK(munmap, 1, syscall_munmap_args, NULL),
#endif
#ifdef SYS_name_to_handle_at
	SYSCALL(name_to_handle_at),
#endif
#ifdef SYS_nanosleep
	SYSCALL_CHK_TIMEOUT(nanosleep, 0, syscall_timespec_timeout, syscall_nanosleep_generic_ret),
#endif
#ifdef SYS_newfstatat
	SYSCALL(newfstatat),
#endif
#ifdef SYS__newselect
	SYSCALL_CHK_TIMEOUT(_newselect, 4, syscall_timeval_timeout, syscall_poll_generic_ret),
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
	SYSCALL_CHK_TIMEOUT(poll, 2, syscall_timeout_millisec, syscall_poll_generic_ret),
#endif
#ifdef SYS_ppoll
	SYSCALL_CHK_TIMEOUT(ppoll, 2, syscall_timespec_timeout, syscall_poll_generic_ret),
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
	SYSCALL_CHK_TIMEOUT(pselect6, 4, syscall_timespec_timeout, syscall_poll_generic_ret),
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
	SYSCALL_CHK(recvfrom, 0, NULL, syscall_recvfrom_ret),
#endif
#ifdef SYS_recvmmsg
	SYSCALL_CHK_TIMEOUT(recvmmsg, 4, syscall_timespec_timeout, NULL),
#endif
#ifdef SYS_recvmsg
	SYSCALL_CHK(recvmsg, 0, NULL, syscall_recvfrom_ret),
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
	SYSCALL_CHK_TIMEOUT(rt_sigtimedwait, 2, syscall_timespec_timeout, syscall_poll_generic_ret),
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
	SYSCALL_CHK_TIMEOUT(select, 4, syscall_timeval_timeout, syscall_poll_generic_ret),
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
	SYSCALL_CHK_TIMEOUT(semtimedop, 3, syscall_timespec_timeout, syscall_semtimedop_ret),
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
	SYSCALL_CHK(sendmsg, 0, NULL, syscall_sendto_ret),
#endif
#ifdef SYS_sendto
	SYSCALL_CHK(sendto, 0, NULL, syscall_sendto_ret),
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
	SYSCALL_CHK(sync, 0, syscall_sync_args, NULL),
#endif
#ifdef SYS_sync_file_range
	SYSCALL_CHK(sync_file_range, 0, syscall_fsync_generic_args, NULL),
#endif
#ifdef SYS_syncfs
	SYSCALL_CHK(syncfs, 0, syscall_fsync_generic_args, NULL),
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
	SYSCALL_CHK(write, 2, syscall_write_args, NULL),
#endif
#ifdef SYS_writev
	SYSCALL(writev),
#endif
};

size_t syscalls_len = ARRAY_SIZE(syscalls);

#endif
