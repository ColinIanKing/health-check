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

#include "list.h"
#include "proc.h"
#include "fnotify.h"
#include "health-check.h"

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
		fprintf(stderr, "Cannot initialize fanotify: %s\n",
			strerror(errno));
		return -1;
	}

	ret = fanotify_mark(fan_fd, FAN_MARK_ADD | FAN_MARK_MOUNT,
		FAN_ACCESS| FAN_MODIFY | FAN_OPEN | FAN_CLOSE |
		FAN_ONDIR | FAN_EVENT_ON_CHILD, AT_FDCWD, "/");
	if (ret < 0) {
		fprintf(stderr, "Cannot add fanotify watch on /: %s\n",
			strerror(errno));
	}

	if ((mounts = setmntent("/proc/self/mounts", "r")) == NULL) {
		fprintf(stderr, "Cannot get mount points\n");
		return -1;
	}

	while ((mount = getmntent (mounts)) != NULL) {
		if (access (mount->mnt_fsname, F_OK) != 0)
			continue;

		ret = fanotify_mark(fan_fd, FAN_MARK_ADD | FAN_MARK_MOUNT,
			FAN_ACCESS| FAN_MODIFY | FAN_OPEN | FAN_CLOSE |
			FAN_ONDIR | FAN_EVENT_ON_CHILD, AT_FDCWD,
			mount->mnt_dir);
		if ((ret < 0) && (errno != ENOENT)) {
			fprintf(stderr, "Cannot add watch on %s mount %s: %s\n",
				mount->mnt_type, mount->mnt_dir,
				strerror (errno));
		}
	}

	endmntent (mounts);

	return fan_fd;
}

void fnotify_event_free(void *data)
{
	fnotify_fileinfo_t *fileinfo = (fnotify_fileinfo_t *)data;

	free(fileinfo->filename);
	free(fileinfo);
}

void fnotify_event_add(
	const list_t *pids,
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

static int fnotify_event_cmp_count(const void *data1, const void *data2)
{
	fnotify_fileinfo_t *info1 = (fnotify_fileinfo_t *)data1;
	fnotify_fileinfo_t *info2 = (fnotify_fileinfo_t *)data2;

	return info2->count - info1->count;
}

static int fnotify_event_cmp_io_ops(const void *data1, const void *data2)
{
	io_ops_t *io_ops1 = (io_ops_t *)data1;
	io_ops_t *io_ops2 = (io_ops_t *)data2;

	return io_ops2->total - io_ops1->total;
}

void fnotify_dump_events(
	const double duration,
	const list_t *pids,
	const list_t *fnotify_files)
{
	link_t 	*l;
	link_t  *lp;
	list_t	sorted;
	int count;
	unsigned long total;
	unsigned long read_total, write_total, open_total, close_total;

	printf("File I/O operations:\n");
	if (fnotify_files->head == NULL) {
		printf(" No file I/O operations detected\n\n");
		return;
	}

	if (!(opt_flags & OPT_BRIEF)) {
		list_init(&sorted);
		for (l = fnotify_files->head; l; l = l->next) {
			fnotify_fileinfo_t *info = (fnotify_fileinfo_t *)l->data;
			list_add_ordered(&sorted, info, fnotify_event_cmp_count);
		}
		printf("  PID  Process               Count  Op  Filename\n");
		for (count = 0, total = 0, l = sorted.head; l; l = l->next) {
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
	
			printf(" %5d %-20.20s %6d %4s %s\n",
				info->proc->pid, info->proc->cmdline,
				info->count, modes, info->filename);
	
			total += info->count;
			count++;
		}
		if (count > 1)
			printf(" %-25.25s%8lu\n", "Total", total);
		printf("\n");
		list_free(&sorted, NULL);
	}

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
			list_add_ordered(&sorted, io_ops, fnotify_event_cmp_io_ops);
	}

	open_total = close_total = read_total = write_total = 0;
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
	} else {
		printf("File I/O Operations per second:\n");
		printf("  PID  Process                 Open   Close    Read   Write\n");
		for (count = 0, l = sorted.head; l; l = l->next) {
			io_ops_t *io_ops = (io_ops_t *)l->data;

			printf(" %5d %-20.20s %7.2f %7.2f %7.2f %7.2f\n",
				io_ops->proc->pid, io_ops->proc->cmdline,
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
	}
	printf("\n");
	list_free(&sorted, free);
}
