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
#include <time.h>
#include <pthread.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <limits.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <math.h>
#include <mntent.h>
#include <sys/fanotify.h>
#include <ctype.h>
#include <dirent.h>

#define APP_NAME			"health-check"

#define HASH_TABLE_SIZE			(1997)
#define ARRAY_SIZE(a)			(sizeof(a) / sizeof(a[0]))
#define TIMER_STATS			"/proc/timer_stats"

#define	OPT_GET_CHILDREN		0x00000001

#define MAX_BUCKET			(11)
#define BUCKET_START			(0.0000001)

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

typedef struct syscall_info {
	pid_t		pid;
	int 		syscall;
	unsigned long	count;
	bool		poll_accounting;
	double 		poll_min;
	double		poll_max;
	double		poll_total;
	unsigned long	poll_count;
	unsigned long	poll_too_low;
	unsigned long	poll_infinite;
	unsigned long	poll_zero;
	unsigned long 	bucket[MAX_BUCKET];
	struct syscall_info *next;
} syscall_info_t;

typedef struct {
	char 		*name;
	int  		syscall;
	bool		do_check;
	int		arg;
	double		*threshold;
	void (*check_func)(int arg, syscall_info_t *s, pid_t pid, double threshold);
} syscall_t;

typedef struct {
	long		padding;
	pid_t		pid;
	pid_t		ppid;
	char		*comm;
	char		*cmdline;
	bool		thread;
	pthread_t	pthread;
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

#define SYSCALL(n) \
	[SYS_ ## n] = { #n, SYS_ ## n, false, 0, NULL, NULL }

#define SYSCALL_TIMEOUT(n, arg, func) \
	[SYS_ ## n] = { #n, SYS_ ## n, true, arg, &timeout[SYS_ ## n], .check_func = func }

typedef void (*list_link_free_t)(void *);
typedef int  (*list_comp_t)(void *, void *);


int  syscall_getargs(pid_t pid, int n_args, unsigned long args[]);
void syscall_check_timeout_ms(int arg, syscall_info_t *s, pid_t pid, double threshold);
void syscall_check_timeout_sec(int arg, syscall_info_t *s, pid_t pid, double threshold);
void syscall_check_timespec(int arg, syscall_info_t *s, pid_t pid, double threshold);
void syscall_check_timeval(int arg, syscall_info_t *s, pid_t pid, double threshold);

static bool keep_running = true;
static int  opt_flags;
static list_t	proc_cache;
static pthread_mutex_t ptrace_mutex = PTHREAD_MUTEX_INITIALIZER;

#define TIMEOUT(n, timeout) \
	[SYS_ ## n] = timeout

static double timeout[] = {
	TIMEOUT(alarm, 1.0),
	TIMEOUT(clock_nanosleep, 1.0),
	TIMEOUT(epoll_pwait, 1.0),
	TIMEOUT(epoll_wait, 1.0),
	TIMEOUT(mq_timedreceive, 1.0),
	TIMEOUT(mq_timedsend, 1.0),
	TIMEOUT(nanosleep, 1.0),
	TIMEOUT(poll, 1.0),
	TIMEOUT(ppoll, 1.0),
	TIMEOUT(pselect6, 1.0),
	TIMEOUT(recvmmsg, 1.0),
	TIMEOUT(rt_sigtimedwait, 1.0),
	TIMEOUT(select, 1.0),
	TIMEOUT(semtimedop, 1.0),
};

static syscall_t syscalls[] = {
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
	SYSCALL_TIMEOUT(alarm, 0, syscall_check_timeout_sec),
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
	SYSCALL_TIMEOUT(clock_nanosleep, 2, syscall_check_timespec),
#endif
#ifdef SYS_clock_settime
	SYSCALL(clock_settime),
#endif
#ifdef SYS_clone
	SYSCALL(clone),
#endif
#ifdef SYS_close
	SYSCALL(close),
#endif
#ifdef SYS_connect
	SYSCALL(connect),
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
	SYSCALL_TIMEOUT(epoll_pwait, 3, syscall_check_timeout_ms),
#endif
#ifdef SYS_epoll_wait
	SYSCALL_TIMEOUT(epoll_wait, 3, syscall_check_timeout_ms),
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
	SYSCALL_TIMEOUT(mq_timedreceive, 4, syscall_check_timespec),
#endif
#ifdef SYS_mq_timedsend
	SYSCALL_TIMEOUT(mq_timedsend, 4, syscall_check_timespec),
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
	SYSCALL_TIMEOUT(nanosleep, 0, syscall_check_timespec),
#endif
#ifdef SYS_newfstatat
	SYSCALL(newfstatat),
#endif
#ifdef SYS__newselect
	SYSCALL(_newselect),
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
	SYSCALL_TIMEOUT(poll, 2, syscall_check_timeout_ms),
#endif
#ifdef SYS_ppoll
	SYSCALL_TIMEOUT(ppoll, 2, syscall_check_timespec),
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
	SYSCALL_TIMEOUT(pselect6, 4, syscall_check_timespec),
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
	SYSCALL_TIMEOUT(recvmmsg, 4, syscall_check_timespec),
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
	SYSCALL_TIMEOUT(rt_sigtimedwait, 2, syscall_check_timespec),
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
	SYSCALL_TIMEOUT(select, 4, syscall_check_timespec),
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
	SYSCALL_TIMEOUT(semtimedop, 3, syscall_check_timespec),
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
	SYSCALL(write),
#endif
#ifdef SYS_writev
	SYSCALL(writev),
#endif
};

syscall_info_t *syscall_info[HASH_TABLE_SIZE];

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

static inline bool syscall_valid(int syscall)
{
	return (syscall > 0) && (syscall <= ARRAY_SIZE(syscalls));
}

int syscall_get_call(pid_t pid)
{
#if defined(__x86_64__)
	return ptrace(PTRACE_PEEKUSER, pid, 8 * ORIG_RAX, NULL);
#elif defined(__i386__)
	return ptrace(PTRACE_PEEKUSER, pid, 4 * ORIG_EAX, NULL);
#elif defined(__arm__)
	struct pt_regs regs;

	if (ptrace(PTRACE_GETREGS, tcp->pid, NULL, (void *)&regs) < 0)
		return -1;

	/* NEEDS IMPLEMENTING! */

	return -1;
#else
#error Only currently implemented for x86 and ARM
#endif
}

int syscall_getargs(pid_t pid, int n_args, unsigned long args[])
{
	if (n_args > 6)
		n_args = 6;
#if defined (I386)
	return 0;
#elif defined (__x86_64__)
	int i;
	long cs;
	int *regs;
	static int regs32[] = { RBX, RCX, RDX, RSI, RDI, RBP};
	static int regs64[] = { RDI, RSI, RDX, R10, R8, R9};

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

	for (i = 0; i <= n_args; i++)
		args[i] = ptrace(PTRACE_PEEKUSER, pid, regs[i] * 8, NULL);
	return 0;
#else
	fprintf(stderr, "Unknown arch\n");
	return -1;
#endif
}

void syscall_name(int syscall, char *name, size_t len)
{
	if (syscall_valid(syscall) && (syscalls[syscall].name)) {
		strncpy(name, syscalls[syscall].name, len);
	} else {
		snprintf(name, len, "SYS_%d", syscall);
	}
}

unsigned long hash_syscall(pid_t pid, int syscall)
{
	unsigned long h;

	h = pid ^ (syscall << 2);
	h %= HASH_TABLE_SIZE;

	return h;
}

int syscall_count_cmp(void *data1, void *data2)
{
	syscall_info_t *s1 = (syscall_info_t *)data1;
	syscall_info_t *s2 = (syscall_info_t *)data2;

	return s2->count - s1->count;
}

void hash_syscall_dump(double duration)
{
	list_t sorted;
	link_t *l;
	int i;

	list_init(&sorted);

	for (i = 0; i < HASH_TABLE_SIZE; i++) {
		syscall_info_t *s;

		for (s = syscall_info[i]; s; s = s->next)
			list_add_ordered(&sorted, s, syscall_count_cmp);
	}

	printf("System Calls Traced:\n");
	printf("Count   PID  Syscall             Rate/Sec\n");
	for (l = sorted.head; l; l = l->next) {
		char name[64];
		syscall_info_t *s = (syscall_info_t *)l->data;
		syscall_name(s->syscall, name, sizeof(name));

		printf("%6lu %5i %-17.17s %12.4f\n",
			s->count, s->pid, name, (double)s->count / duration);
	}

	list_free(&sorted, NULL);
}

void syscall_check_timeout(syscall_info_t *s, double timeout, double threshold)
{
	double t = BUCKET_START;
	int bucket = 0;

	while (t <= timeout) {
		bucket++;
		t *= 10;
	}

	pthread_mutex_lock(&ptrace_mutex);
	s->poll_accounting = true;
	s->poll_count++;

	/*  Indefinite waits we ignore in the stats */
	if (timeout < 0.0) {
		s->poll_infinite++;
		pthread_mutex_unlock(&ptrace_mutex);
		return;
	}

	if (timeout == 0.0) {
		s->poll_zero++;
		s->poll_too_low++;
		pthread_mutex_unlock(&ptrace_mutex);
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
	s->poll_total += timeout;
	s->bucket[bucket]++;
	if (timeout <= threshold)
		s->poll_too_low++;

	pthread_mutex_unlock(&ptrace_mutex);
}

void syscall_get_arg_data(unsigned long addr, pid_t pid, void *data, ssize_t len)
{
	size_t n = (len + sizeof(unsigned long) - 1) / sizeof(unsigned long);
	unsigned long tmpdata[n];
	int i;

	for (i = 0; i < n; i++)
		tmpdata[i] = ptrace(PTRACE_PEEKDATA, pid, addr + (sizeof(unsigned long) * i), NULL);

	memcpy(data, tmpdata, len);
}

void syscall_check_timeval(int arg, syscall_info_t *s, pid_t pid, double threshold)
{
	unsigned long args[arg + 1];
	struct timeval timeout;
	double t;

	syscall_getargs(pid, arg, args);
	if (args[arg] == 0)
		return;

	syscall_get_arg_data(args[arg], pid, &timeout, sizeof(timeout));
	t = timeout.tv_sec + (timeout.tv_usec / 1000000.0);

	syscall_check_timeout(s, t, threshold);
}

void syscall_check_timespec(int arg, syscall_info_t *s, pid_t pid, double threshold)
{
	unsigned long args[arg + 1];
	struct timespec timeout;
	double t;

	syscall_getargs(pid, arg, args);
	if (args[arg] == 0)
		return;

	syscall_get_arg_data(args[arg], pid, &timeout, sizeof(timeout));
	t = timeout.tv_sec + (timeout.tv_nsec / 1000000000.0);

	syscall_check_timeout(s, t, threshold);
}

void syscall_check_timeout_ms(int arg, syscall_info_t *s, pid_t pid, double threshold)
{
	unsigned long args[arg + 1];

	syscall_getargs(pid, arg, args);
	syscall_check_timeout(s, (double)(int)args[arg] / 1000.0, threshold);
}

void syscall_check_timeout_sec(int arg, syscall_info_t *s, pid_t pid, double threshold)
{
	unsigned long args[arg + 1];

	syscall_getargs(pid, arg, args);
	syscall_check_timeout(s, (double)args[arg], threshold);
}

char *format_time(char *buffer, size_t len, double t, bool end)
{
	char *units[] = { "s ", "ms", "us", "ns", "ps" };
	int i;

	for (i = 0; t != 0.0 && t < 0.99999; i++)
		t *= 1000.0;

	if (end) {
		if (t - 0.1 < 0.99999) {
			t *= 1000.0;
			i++;
		}
		t -= 0.1;
	}

	snprintf(buffer, len, "%5.1f %s", t, units[i]);
	return buffer;
}

void syscall_pollers(double duration)
{
	int i;
	list_t sorted;
	link_t *l;

	list_init(&sorted);

	for (i = 0; i < HASH_TABLE_SIZE; i++) {
		syscall_info_t *s;

		for (s = syscall_info[i]; s; s = s->next) {
			if (syscalls[s->syscall].do_check) {
				list_add_ordered(&sorted, s, syscall_count_cmp);
				break;
			}
		}
	}

	if (sorted.head) {
		double prev, bucket = BUCKET_START;

		printf("\nTop Polling System Calls:\n");
		printf("Count   PID  Syscall             Rate/Sec   Infinite   Zero       Minimum        Maximum        Average     %% BAD\n");
		printf("                                            Timeouts Timeouts   Timeout (Sec)  Timeout (Sec)  Timeout (Sec) Polling\n");
		for (l = sorted.head; l; l = l->next) {
			char name[64];
			syscall_info_t *s = (syscall_info_t *)l->data;
			syscall_name(s->syscall, name, sizeof(name));

			printf("%6lu %5i %-17.17s %12.4f",
				s->count, s->pid, name,
				(double)s->count / duration);

			if (s->poll_accounting)  {
				printf(" %8lu %8lu ", s->poll_infinite, s->poll_zero);
				if (s->poll_count)
					printf(" %14.8f %14.8f %14.8f %6.2f",
						s->poll_min < 0.0 ? 0.0 : s->poll_min,
						s->poll_max < 0.0 ? 0.0 : s->poll_max,
						(double)s->poll_total / (double)s->count,
						100.0 * (double)s->poll_too_low / (double)s->poll_count);
				else
					printf("       n/a            n/a            n/a        n/a");
			}
			printf("\n");
		}

		printf("\nDistribution of poll timeout times:\n");
		printf("          System call : ");
		for (l = sorted.head; l; l = l->next) {
			char name[32];
			syscall_info_t *s = (syscall_info_t *)l->data;
			syscall_name(s->syscall, name, sizeof(name));
			printf("%10.10s ", name);
		}
		printf("\n");
		printf("                  PID : ");
		for (l = sorted.head; l; l = l->next) {
			syscall_info_t *s = (syscall_info_t *)l->data;
			printf("    %6u ", s->pid);
		}
		printf("\n");
		printf("                 zero :");
		for (l = sorted.head; l; l = l->next) {
			syscall_info_t *s = (syscall_info_t *)l->data;
			printf(" %10lu", s->poll_zero);
		}
		printf("\n");

		for (i = 0; i < MAX_BUCKET; i++) {
			char t1[64], t2[64];
			format_time(t1, sizeof(t1), prev, false);
			format_time(t2, sizeof(t2), bucket, true);
			printf("%9.9s - %9.9s :",
				i == 0 ? "" : t1,
				i == (MAX_BUCKET-1) ? "" : t2);

			for (l = sorted.head; l; l = l->next) {
				syscall_info_t *s = (syscall_info_t *)l->data;
				printf(" %10lu", s->bucket[i]);
			}
			printf("\n");
			prev = bucket;
			bucket *= 10;
		}
		printf("           indefinite :");
		for (l = sorted.head; l; l = l->next) {
			syscall_info_t *s = (syscall_info_t *)l->data;
			printf(" %10lu", s->poll_infinite);
		}
		printf("\n");
	}

	list_free(&sorted, NULL);
}

void syscall_count(pid_t pid, int syscall)
{
	unsigned long h = hash_syscall(pid, syscall);
	syscall_info_t *s;
	bool valid = syscall_valid(syscall);
	syscall_t *sc;

	pthread_mutex_lock(&ptrace_mutex);

	for (s = syscall_info[h]; s; s = s->next) {
		if ((s->syscall == syscall) &&
		    (s->pid == pid)) {
			s->count++;
			pthread_mutex_unlock(&ptrace_mutex);

			if (valid) {
				sc = &syscalls[syscall];
				if (sc->check_func) {
					sc->check_func(sc->arg, s, pid, *(sc->threshold));
				}
			}
			return;
		}
	}
	pthread_mutex_unlock(&ptrace_mutex);

	if ((s = calloc(1, sizeof(*s))) == NULL) {
		fprintf(stderr, "Cannot allocate syscall hash item\n");
		exit(EXIT_FAILURE);
	}

	s->syscall = syscall;
	s->pid = pid;
	s->count = 1;
	s->poll_accounting = false;
	s->poll_zero = 0;
	s->poll_infinite = 0;
	s->poll_count = 0;
	s->poll_min = -1.0;
	s->poll_max = -1.0;
	s->poll_total = 0;
	s->poll_too_low = 0;

	pthread_mutex_lock(&ptrace_mutex);
	s->next = syscall_info[h];
	syscall_info[h] = s;
	pthread_mutex_unlock(&ptrace_mutex);

	if (valid) {
		sc = &syscalls[syscall];
		if (sc->check_func)
			sc->check_func(sc->arg, s, pid, *(sc->threshold));
	}
}

int syscall_wait(const pid_t pid)
{
	for (;;) {
		int status;
		ptrace(PTRACE_SYSCALL, pid, 0, 0);
		waitpid(pid, &status, 0);
		if (WIFSTOPPED(status) &&
		    WSTOPSIG(status) & 0x80)
			return 0;
		if (WIFEXITED(status))
			return 1;
	}
}

void *syscall_trace(void *arg)
{
	int status, syscall;
	pid_t pid = *((pid_t*)arg);

	waitpid(pid, &status, 0);
	ptrace(PTRACE_ATTACH, pid, 0, 0);
	waitpid(pid, &status, 0);
	ptrace(PTRACE_SETOPTIONS, pid, 0, PTRACE_O_TRACESYSGOOD);

	while (keep_running) {
		if (syscall_wait(pid))
			break;

		syscall = syscall_get_call(pid);
		syscall_count(pid, syscall);

		if (syscall_wait(pid))
			break;
	}

	pthread_exit(0);
}

static void handle_sigint(int dummy)
{
	(void)dummy;    /* Stop unused parameter warning with -Wextra */

	keep_running = false;
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
 *  Stop gcc complaining about no return func
 */
static void health_check_exit(const int status) __attribute__ ((noreturn));



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

	if (pid == getpid()) {
		/* We never should monitor oneself, it gets messy */
		return NULL;
	}

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
	for (l = pids.head; l; l = l->next) {
		proc_info_t *p = (proc_info_t *)l->data;
		if (!p->thread)
			pthread_create(&p->pthread, NULL, syscall_trace, &p->pid);
	}

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

	hash_syscall_dump(actual_duration);
	syscall_pollers(actual_duration);

out:
	free(buffer);
	list_free(&pids, NULL);
	list_free(&event_info_old, event_free);
	list_free(&event_info_new, event_free);
	list_free(&cpustat_info_old, free);
	list_free(&cpustat_info_new, free);
	list_free(&fnotify_files, fnotify_event_free);
	list_free(&proc_cache, free_pid_info);

	pthread_mutex_destroy(&ptrace_mutex);

	health_check_exit(EXIT_SUCCESS);
}
