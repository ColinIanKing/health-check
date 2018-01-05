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

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <limits.h>
#include <errno.h>
#include <mntent.h>
#include <fcntl.h>
#include <sys/fanotify.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>

#include "list.h"
#include "json.h"
#include "proc.h"
#include "fnotify.h"
#include "health-check.h"

static list_t fnotify_files, fnotify_wakelocks;

/*
 *  fnotify_event_init()
 *	initialize fnotify
 */
int fnotify_event_init(void)
{
	int fan_fd;
	int ret;
	FILE* mounts;
	struct mntent* mount;

	if ((fan_fd = fanotify_init (0, 0)) < 0) {
		fprintf(stderr, "Cannot initialize fanotify: %s.\n",
			strerror(errno));
		return -1;
	}

	ret = fanotify_mark(fan_fd, FAN_MARK_ADD | FAN_MARK_MOUNT,
		FAN_ACCESS| FAN_MODIFY | FAN_OPEN | FAN_CLOSE |
		FAN_ONDIR | FAN_EVENT_ON_CHILD, AT_FDCWD, "/");
	if (ret < 0) {
		fprintf(stderr, "Cannot add fanotify watch on /: %s.\n",
			strerror(errno));
	}

	if ((mounts = setmntent("/proc/self/mounts", "r")) == NULL) {
		fprintf(stderr, "Cannot get mount points.\n");
		return -1;
	}

	while ((mount = getmntent (mounts)) != NULL) {
		/*
		if (access (mount->mnt_fsname, F_OK) != 0)
			continue;
		*/

		ret = fanotify_mark(fan_fd, FAN_MARK_ADD | FAN_MARK_MOUNT,
			FAN_ACCESS| FAN_MODIFY | FAN_OPEN | FAN_CLOSE |
			FAN_ONDIR | FAN_EVENT_ON_CHILD, AT_FDCWD,
			mount->mnt_dir);
		if ((ret < 0) && (errno != ENOENT)) {
			continue;
		}
	}
	endmntent (mounts);

	/* Track /sys/power ops for wakealarm analysis */
	(void)fanotify_mark(fan_fd, FAN_MARK_ADD,
		FAN_ACCESS | FAN_MODIFY, AT_FDCWD,
		"/sys/power/wake_lock");
	(void)fanotify_mark(fan_fd, FAN_MARK_ADD,
		FAN_ACCESS | FAN_MODIFY, AT_FDCWD,
		"/sys/power/wake_unlock");

	return fan_fd;
}

/*
 *  fnotify_event_free()
 *	free event info
 */
static void fnotify_event_free(void *data)
{
	fnotify_fileinfo_t *fileinfo = (fnotify_fileinfo_t *)data;

	free(fileinfo->filename);
	free(fileinfo);
}

/*
 *  fnotify_get_filename()
 *	look up a in-use file descriptor from a given pid
 *	and find the associated filename
 */
char *fnotify_get_filename(const pid_t pid, const int fd)
{
	char 	buf[256];
	char 	path[PATH_MAX];
	ssize_t len;
	char 	*filename;

	/*
	 * With fnotifies, fd of the file is added to the process
	 * fd array, so we just pick them up from /proc/self. Use
	 * a pid of -1 for self
	 */
	if (pid == -1)
		snprintf(buf, sizeof(buf), "/proc/self/fd/%d", fd);
	else
		snprintf(buf, sizeof(buf), "/proc/%d/fd/%d", pid, fd);

	len = readlink(buf, path, sizeof(path));
	if (len < 0) {
		struct stat statbuf;
		if (fstat(fd, &statbuf) < 0)
			filename = strdup("(unknown)");
		else {
			snprintf(buf, sizeof(buf), "dev: %i:%i inode %ld",
				major(statbuf.st_dev), minor(statbuf.st_dev), statbuf.st_ino);
			filename = strdup(buf);
		}
	} else {
		/*
		 *  In an ideal world we should allocate the path
		 *  based on a lstat'd size, but because this can be
		 *  racey on has to re-check, which involves
		 *  re-allocing the buffer.  Since we need to be
		 *  fast let's just fetch up to PATH_MAX-1 of data.
		 */
		path[len >= PATH_MAX ? PATH_MAX - 1 : len] = '\0';
		filename = strdup(path);
	}
	return filename;
}

/*
 *  fnotify_event_add()
 *	add a new fnotify event
 */
int fnotify_event_add(
	const list_t *pids,
	const struct fanotify_event_metadata *metadata)
{
	link_t *l;

	if ((metadata->fd == FAN_NOFD) && (metadata->fd < 0))
		return 0;

	for (l = pids->head; l; l = l->next) {
		 proc_info_t *p = (proc_info_t*)l->data;

		if (metadata->pid == p->pid) {
			char 	*filename = fnotify_get_filename(-1, metadata->fd);

			if (filename == NULL) {
				health_check_out_of_memory("allocating fnotify filename");
				(void)close(metadata->fd);
				return -1;
			}
			if ((opt_flags & OPT_WAKELOCKS_LIGHT) &&
			    (metadata->mask & (FAN_MODIFY | FAN_CLOSE_WRITE)) &&
			    (!strcmp(filename, "/sys/power/wake_lock") ||
			     !strcmp(filename, "/sys/power/wake_unlock"))) {
				fnotify_wakelock_info_t	*wakelock_info;
				link_t	*wl;
				bool	found = false;

				for (wl = fnotify_wakelocks.head; wl; wl = wl->next) {
					wakelock_info = (fnotify_wakelock_info_t *)wl->data;
					if (wakelock_info->proc == p) {
						found = true;
						break;
					}
				}

				if (!found) {
					if ((wakelock_info = calloc(1, sizeof(*wakelock_info))) == NULL) {
						health_check_out_of_memory("allocating wakelock information");
						free(filename);
						(void)close(metadata->fd);
						return -1;
					}
					wakelock_info->proc = p;
					wakelock_info->locked = 0;
					wakelock_info->unlocked = 0;
					wakelock_info->total = 0;
					if (list_append(&fnotify_wakelocks, wakelock_info) == NULL) {
						free(filename);
						(void)close(metadata->fd);
						return -1;
					}
				}

				if (strcmp(filename, "/sys/power/wake_unlock"))
					wakelock_info->locked++;
				else
					wakelock_info->unlocked++;

				free(filename);
				wakelock_info->total++;
			} else {
				fnotify_fileinfo_t *fileinfo;
				link_t	*fl;
				bool	found = false;

				for (fl = fnotify_files.head; fl; fl = fl->next) {
					fileinfo = (fnotify_fileinfo_t *)fl->data;
					if ((metadata->mask == fileinfo->mask) &&
					    (!strcmp(fileinfo->filename, filename))) {
						found = true;
						break;
					}
				}

				if (!found) {
					if ((fileinfo = calloc(1, sizeof(*fileinfo))) == NULL) {
						health_check_out_of_memory("allocating fnotify file information");
						free(filename);
						(void)close(metadata->fd);
						return -1;
					}
					fileinfo->filename = filename;
					fileinfo->mask = metadata->mask;
					fileinfo->proc = p;
					fileinfo->count = 0;
					if (list_append(&fnotify_files, fileinfo) == NULL) {
						free(filename);
						(void)close(metadata->fd);
						return -1;
					}
				} else {
					free(filename);
				}
				fileinfo->count++;
			}
		}
	}
	(void)close(metadata->fd);

	return 0;
}

/*
 *  fnotify_event_cmp_count()
 *	for list sorting, compare counts
 */
static int fnotify_event_cmp_count(const void *data1, const void *data2)
{
	const fnotify_fileinfo_t *info1 = (const fnotify_fileinfo_t *)data1;
	const fnotify_fileinfo_t *info2 = (const fnotify_fileinfo_t *)data2;

	return info2->count - info1->count;
}

/*
 *  fnotify_event_cmp_io_ops()
 *	for list sorting, compare io op totals
 */
static int fnotify_event_cmp_io_ops(const void *data1, const void *data2)
{
	const io_ops_t *io_ops1 = (const io_ops_t *)data1;
	const io_ops_t *io_ops2 = (const io_ops_t *)data2;

	return io_ops2->total - io_ops1->total;
}

/*
 *  fnotify_wakelock_cmp_count()
 *	for list sorting, compare wakelock totals
 */
static int fnotify_wakelock_cmp_count(const void *data1, const void *data2)
{
	const fnotify_wakelock_info_t *w1 = (const fnotify_wakelock_info_t *)data1;
	const fnotify_wakelock_info_t *w2 = (const fnotify_wakelock_info_t *)data2;

	return w2->total - w1->total;
}

/*
 *  fnotify_mask_to_str()
 *	convert fnotify mask to readable string
 */
static const char *fnotify_mask_to_str(const int mask)
{
	static char modes[5];
	int i = 0;

	if (mask & FAN_OPEN)
		modes[i++] = 'O';
	if (mask & (FAN_CLOSE_WRITE | FAN_CLOSE_NOWRITE))
		modes[i++] = 'C';
	if (mask & FAN_ACCESS)
		modes[i++] = 'R';
	if (mask & (FAN_MODIFY | FAN_CLOSE_WRITE))
		modes[i++] = 'W';
	modes[i] = '\0';

	return modes;
}

/*
 *  fnotify_dump_files()
 *	dump out fnotify file access stats
 */
static void fnotify_dump_files(
	json_object *j_tests,
	const double duration)
{
	list_t	sorted;
	link_t 	*l;
	int count;
	uint64_t total;
	const int pid_size = pid_max_digits();

#ifndef JSON_OUTPUT
	(void)j_tests;
	(void)duration;
#endif
	list_init(&sorted);
	for (l = fnotify_files.head; l; l = l->next) {
		fnotify_fileinfo_t *info = (fnotify_fileinfo_t *)l->data;
		if (list_add_ordered(&sorted, info, fnotify_event_cmp_count) == NULL)
			goto out;
	}
	if (fnotify_files.head && !(opt_flags & OPT_BRIEF)) {
		printf(" %*s Process               Count  Op  Filename\n",
			pid_size, "PID");
		for (count = 0, total = 0, l = sorted.head; l; l = l->next) {
			fnotify_fileinfo_t *info = (fnotify_fileinfo_t *)l->data;

			printf(" %*d %-20.20s %6" PRIu64 " %4s %s\n",
				pid_size, info->proc->pid,
				info->proc->cmdline,
				info->count,
				fnotify_mask_to_str(info->mask),
				info->filename);
			total += info->count;
			count++;
		}
		if (count > 1)
			printf(" %-25.25s%8" PRIu64 "\n", "Total", total);
		printf(" Op: O=Open, R=Read, W=Write, C=Close\n\n");
	}

#ifdef JSON_OUTPUT
	if (j_tests) {
		json_object *j_fnotify_test, *j_accesses, *j_access;

		if ((j_fnotify_test = j_obj_new_obj()) == NULL)
			goto out;
		j_obj_obj_add(j_tests, "file-access", j_fnotify_test);
		if ((j_accesses = j_obj_new_array()) == NULL)
			goto out;
		j_obj_obj_add(j_fnotify_test, "file-access-per-process", j_accesses);

		for (total = 0, l = sorted.head; l; l = l->next) {
			fnotify_fileinfo_t *info = (fnotify_fileinfo_t *)l->data;

			if ((j_access = j_obj_new_obj()) == NULL)
				goto out;
                        j_obj_new_int32_add(j_access, "pid", info->proc->pid);
                        j_obj_new_int32_add(j_access, "ppid", info->proc->ppid);
                        j_obj_new_int32_add(j_access, "is-thread", info->proc->is_thread);
                        j_obj_new_string_add(j_access, "name", info->proc->cmdline);
			j_obj_new_string_add(j_access, "access-mode", fnotify_mask_to_str(info->mask));
			j_obj_new_string_add(j_access, "filename", info->filename);
                        j_obj_new_int64_add(j_access, "accesses-count", info->count);
                        j_obj_new_double_add(j_access, "accesses-count-rate", (double)info->count / duration);
			j_obj_array_add(j_accesses, j_access);
			total += info->count;
		}
		if ((j_access = j_obj_new_obj()) == NULL)
			goto out;
		j_obj_obj_add(j_fnotify_test, "file-access-total", j_access);
		j_obj_new_int64_add(j_access, "access-count-total", total);
		j_obj_new_double_add(j_access, "access-count-total-rate", (double)total / duration);
	}
#endif

out:
	list_free(&sorted, NULL);

}

/*
 *  fnotify_dump_io_ops()
 *	dump out fnotify I/O operations
 */
static void fnotify_dump_io_ops(
	json_object *j_tests,
	const double duration,
	const list_t *pids)
{
	link_t 	*l, *lp;
	list_t	sorted;
	int count;
	uint64_t read_total, write_total, open_total, close_total;
#ifndef JSON_OUTPUT
	(void)j_tests;
#endif

	list_init(&sorted);
	for (lp = pids->head; lp; lp = lp->next) {
		proc_info_t *p = (proc_info_t*)lp->data;
		io_ops_t io_ops;

		memset(&io_ops, 0, sizeof(io_ops));
		io_ops.proc = p;

		for (l = fnotify_files.head; l; l = l->next) {
			fnotify_fileinfo_t *info = (fnotify_fileinfo_t *)l->data;

			if (info->proc->pid != p->pid)
				continue;
			if (info->mask & FAN_OPEN)
				io_ops.open_total += info->count;
			if (info->mask & (FAN_CLOSE_WRITE | FAN_CLOSE_NOWRITE))
				io_ops.close_total += info->count;
			if (info->mask & FAN_ACCESS)
				io_ops.read_total += info->count;
			if (info->mask & (FAN_MODIFY | FAN_CLOSE_WRITE))
				io_ops.write_total += info->count;
		}
		io_ops.total = io_ops.open_total + io_ops.close_total +
			       io_ops.read_total + io_ops.write_total;

		if (io_ops.total) {
			io_ops_t *new_io_ops;

			if ((new_io_ops = calloc(1, sizeof(*new_io_ops))) == NULL) {
				health_check_out_of_memory("allocating fnotify I/O ops information");
				goto out;
			}
			*new_io_ops = io_ops;
			if (list_add_ordered(&sorted, new_io_ops, fnotify_event_cmp_io_ops) == NULL) {
				free(new_io_ops);
				goto out;
			}
		}
	}

	open_total = close_total = read_total = write_total = 0;
	if (fnotify_files.head) {
		if (opt_flags & OPT_BRIEF) {
			for (l = sorted.head; l; l = l->next) {
				io_ops_t *io_ops = (io_ops_t *)l->data;
				open_total  += io_ops->open_total;
				close_total += io_ops->close_total;
				read_total  += io_ops->read_total;
				write_total += io_ops->write_total;
			}
			printf("  I/O Operations per second: %.2f open, %.2f close, %.2f read, %.2f write\n",
				(double)open_total / duration,
				(double)close_total / duration,
				(double)read_total / duration,
				(double)write_total / duration);
			printf("\n");
		} else {
			const int pid_size = pid_max_digits();

			printf("File I/O Operations per second:\n");
			printf(" %*s Process                 Open   Close    Read   Write\n",
				pid_size, "PID");
			for (count = 0, l = sorted.head; l; l = l->next) {
				io_ops_t *io_ops = (io_ops_t *)l->data;

				printf(" %*d %-20.20s %7.2f %7.2f %7.2f %7.2f\n",
					pid_size, io_ops->proc->pid,
					io_ops->proc->cmdline,
					(double)io_ops->open_total / duration,
					(double)io_ops->close_total / duration,
					(double)io_ops->read_total / duration,
					(double)io_ops->write_total / duration);

				open_total  += io_ops->open_total;
				close_total += io_ops->close_total;
				read_total  += io_ops->read_total;
				write_total += io_ops->write_total;
				count++;
			}
			if (count > 1) {
				printf(" %-27.27s%7.2f %7.2f %7.2f %7.2f\n",
					"Total",
					(double)open_total / duration,
					(double)close_total / duration,
					(double)read_total / duration,
					(double)write_total / duration);
			}
			printf("\n");
		}
	}

#ifdef JSON_OUTPUT
	if (j_tests) {
		json_object *j_fnotify_test, *j_io_ops, *j_io_op;

		if ((j_fnotify_test = j_obj_new_obj()) == NULL)
			goto out;
		j_obj_obj_add(j_tests, "file-io-operations", j_fnotify_test);
		if ((j_io_ops = j_obj_new_array()) == NULL)
			goto out;
		j_obj_obj_add(j_fnotify_test, "file-io-operations-per-process", j_io_ops);

		for (l = sorted.head; l; l = l->next) {
			io_ops_t *io_ops = (io_ops_t *)l->data;

			if ((j_io_op = j_obj_new_obj()) == NULL)
				goto out;
                        j_obj_new_int32_add(j_io_op, "pid", io_ops->proc->pid);
                        j_obj_new_int32_add(j_io_op, "ppid", io_ops->proc->ppid);
                        j_obj_new_int32_add(j_io_op, "is-thread", io_ops->proc->is_thread);
                        j_obj_new_string_add(j_io_op, "name", io_ops->proc->cmdline);
			j_obj_new_int64_add(j_io_op, "open-call-count", io_ops->open_total);
			j_obj_new_int64_add(j_io_op, "close-call-count", io_ops->close_total);
			j_obj_new_int64_add(j_io_op, "read-call-count", io_ops->read_total);
			j_obj_new_int64_add(j_io_op, "write-call-count", io_ops->write_total);

			j_obj_new_double_add(j_io_op, "open-call-rate", (double)io_ops->open_total / duration);
			j_obj_new_double_add(j_io_op, "close-call-rate", (double)io_ops->close_total / duration);
			j_obj_new_double_add(j_io_op, "read-call-rate", (double)io_ops->read_total / duration);
			j_obj_new_double_add(j_io_op, "write-call-rate", (double)io_ops->write_total / duration);
			j_obj_array_add(j_io_ops, j_io_op);
		}
		if ((j_io_op = j_obj_new_obj()) == NULL)
			goto out;
		j_obj_obj_add(j_fnotify_test, "file-io-operations-total", j_io_op);

		j_obj_new_int64_add(j_io_op, "open-call-total", open_total);
		j_obj_new_int64_add(j_io_op, "close-call-total", close_total);
		j_obj_new_int64_add(j_io_op, "read-total", read_total);
		j_obj_new_int64_add(j_io_op, "write-call-total", write_total);

		j_obj_new_double_add(j_io_op, "open-call-total-rate", (double)open_total / duration);
		j_obj_new_double_add(j_io_op, "close-call-total-rate", (double)close_total / duration);
		j_obj_new_double_add(j_io_op, "read-call-total-rate", (double)read_total / duration);
		j_obj_new_double_add(j_io_op, "write-call-total-rate", (double)write_total / duration);
	}
#endif

out:
	list_free(&sorted, free);
}

/*
 *  fnotify_dump_wakelocks()
 *	dump out fnotify wakelock operations
 */
void fnotify_dump_wakelocks(
	json_object *j_tests,
	const double duration)
{
	list_t	sorted;
	link_t 	*l;

	(void)j_tests;
	(void)duration;

	if (!(opt_flags & OPT_WAKELOCKS_LIGHT))
		return;

	printf("Wakelock operations:\n");

	list_init(&sorted);
	for (l = fnotify_wakelocks.head; l; l = l->next) {
		fnotify_wakelock_info_t *info = (fnotify_wakelock_info_t *)l->data;
		if (list_add_ordered(&sorted, info, fnotify_wakelock_cmp_count) == NULL)
			goto out;
	}

	if (!fnotify_wakelocks.head) {
		printf(" None.\n\n");
	} else {
		if (fnotify_wakelocks.head && !(opt_flags & OPT_BRIEF)) {
			const int pid_size = pid_max_digits();

			printf(" %*s Process                 Locks  Unlocks\n",
				pid_size, "PID");

			for (l = sorted.head; l; l = l->next) {
				fnotify_wakelock_info_t *info = (fnotify_wakelock_info_t *)l->data;
				printf(" %*d %-20.20s %8" PRIu64 " %8" PRIu64 "\n",
					pid_size, info->proc->pid,
					info->proc->cmdline,
					info->locked, info->unlocked);
			}
		}
		printf("\n");
	}

#ifdef JSON_OUTPUT
	if (j_tests) {
		json_object *j_wakelock_test, *j_wakelock_infos, *j_wakelock_info;
		uint64_t locked_total = 0, unlocked_total = 0;

		if ((j_wakelock_test = j_obj_new_obj()) == NULL)
			goto out;
		j_obj_obj_add(j_tests, "wakelock-operations-light", j_wakelock_test);
		if ((j_wakelock_infos = j_obj_new_array()) == NULL)
			goto out;
		j_obj_obj_add(j_wakelock_test, "wakelock-operations-light-per-process", j_wakelock_infos);

		for (l = sorted.head; l; l = l->next) {
			fnotify_wakelock_info_t *info = (fnotify_wakelock_info_t *)l->data;

			if ((j_wakelock_info = j_obj_new_obj()) == NULL)
				goto out;
                        j_obj_new_int32_add(j_wakelock_info, "pid", info->proc->pid);
                        j_obj_new_int32_add(j_wakelock_info, "ppid", info->proc->ppid);
                        j_obj_new_int32_add(j_wakelock_info, "is-thread", info->proc->is_thread);
                        j_obj_new_string_add(j_wakelock_info, "name", info->proc->cmdline);
			j_obj_new_int64_add(j_wakelock_info, "wakelock-locked", info->locked);
			j_obj_new_double_add(j_wakelock_info, "wakelock-locked-rate", (double)info->locked / duration);
			j_obj_new_int64_add(j_wakelock_info, "wakelock-unlocked", info->unlocked);
			j_obj_new_double_add(j_wakelock_info, "wakelock-unlocked-rate", (double)info->unlocked / duration);
			j_obj_array_add(j_wakelock_infos, j_wakelock_info);

			locked_total += info->locked;
			unlocked_total += info->unlocked;
		}
		if ((j_wakelock_info = j_obj_new_obj()) == NULL)
			goto out;
		j_obj_obj_add(j_wakelock_test, "wakelock-operations-light-total", j_wakelock_info);
		j_obj_new_int64_add(j_wakelock_info, "wakelock-locked-total", locked_total);
		j_obj_new_double_add(j_wakelock_info, "wakelock-locked-total-rate", (double)locked_total / duration);
		j_obj_new_int64_add(j_wakelock_info, "wakelock-unlocked-total", unlocked_total);
		j_obj_new_double_add(j_wakelock_info, "wakelock-unlocked-total-rate", (double)unlocked_total / duration);
	}
#endif
out:
	list_free(&sorted, NULL);
}


/*
 *  fnotify_dump_events()
 *	dump out fnotify file access events
 */
void fnotify_dump_events(
	json_object *j_tests,
	const double duration,
	const list_t *pids)
{
	printf("File I/O operations:\n");
	if (!fnotify_files.head)
		printf(" No file I/O operations detected.\n\n");

	fnotify_dump_files(j_tests, duration);
	fnotify_dump_io_ops(j_tests, duration, pids);
}

/*
 *  fnotify_init()
 *	initialize fnotify lists
 */
void fnotify_init(void)
{
	list_init(&fnotify_files);
	list_init(&fnotify_wakelocks);
}

/*
 *  fnotify_cleanup()
 *	free fnotify lists
 */
void fnotify_cleanup(void)
{
	list_free(&fnotify_files, fnotify_event_free);
	list_free(&fnotify_wakelocks, free);
}
