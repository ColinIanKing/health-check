/*
 * Copyright (C) 2013-2020 Canonical, Ltd.
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

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <inttypes.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <ctype.h>

#include "list.h"
#include "mem.h"
#include "health-check.h"

static list_t mem_info_old, mem_info_new;
static list_t mem_brk_info;
static list_t mem_mmap_info;

static const char *mem_types[] = {
	"Stack",
	"Heap",
	"Mapped",
};

#ifdef JSON_OUTPUT
/*
 *  mem_tolower_str()
 *	string to lower case
 */
static void mem_tolower_str(char *str)
{
	for (;*str; str++)
		*str = tolower(*str);
}
#endif

/*
 *  mem_loading()
 *	convert heath growth rate into human readable form
 */
static const char *mem_loading(const double mem_rate)
{
	char *verb, *adverb;
	static char buffer[64];
	double rate = mem_rate;

	if (FLOAT_CMP(rate, 0.0))
		return "no change";
	if (rate < 0) {
		verb = "shrinking";
		rate = -mem_rate;
	} else
		verb = "growing";

	if (rate < 1024.0)
		adverb = " slowly";
	else if (rate >= 2.0 * 1024.0  * 1024.0)
		adverb = " very fast";
	else if (rate >= 256.0 * 1024.0)
		adverb = " fast";
	else if (rate >= 8.0 * 1024.0)
		adverb = " moderately fast";
	else
		adverb = "";

	sprintf(buffer, "%s%s", verb, adverb);
	return buffer;
}

/*
 *  mem_mmap_account()
 *	do mmap/munmap accounting on pid of map size length.
 */
int mem_mmap_account(const pid_t pid, const size_t length, const bool mmap)
{
	link_t *l;
	bool found = false;

	mem_mmap_info_t *info = NULL;

	for (l = mem_mmap_info.head; l; l = l->next) {
		info = (mem_mmap_info_t *)l->data;
		if (info->pid == pid) {
			found = true;
			break;
		}
	}
	if (!found) {
		if ((info = calloc(1, sizeof(*info))) == NULL) {
			health_check_out_of_memory("allocating memory tracking brk() information");
			return -1;
		}
		info->pid = pid;
		if (list_append(&mem_mmap_info, info) == NULL) {
			free(info);
			return -1;
		}
	}

	if (mmap) {
		info->mmap_count++;
		info->mmap_length += length;
	} else {
		info->munmap_count++;
		info->munmap_length += length;
	}
	return 0;
}

/*
 *  mem_mmap_cmp()
 *	list sorting based on total mmap size
 */
static int mem_mmap_cmp(const void *data1, const void *data2)
{
	const mem_mmap_info_t *m1 = (const mem_mmap_info_t *)data1;
	const mem_mmap_info_t *m2 = (const mem_mmap_info_t *)data2;
	const int64_t d1 = m1->mmap_length - m1->munmap_length;
	const int64_t d2 = m2->mmap_length - m2->munmap_length;

	return d2 - d1;
}

/*
 *  mem_dump_mmap()
 *	dump mmap changes
 */
void mem_dump_mmap(json_object *j_tests, const double duration)
{
	list_t sorted;
	link_t *l;
	mem_mmap_info_t *info;

#if !defined(JSON_OUTPUT)
	(void)j_tests;
#endif

	printf("Memory Change via mmap() and munmap():\n");

	list_init(&sorted);
	for (l = mem_mmap_info.head; l; l = l->next) {
		info = (mem_mmap_info_t *)l->data;
		if (list_add_ordered(&sorted, info, mem_mmap_cmp) == NULL)
			goto out;
	}

	if (mem_mmap_info.head == NULL) {
		printf(" None.\n\n");
	} else {
		const int pid_size = pid_max_digits();

		printf(" %*s                         mmaps  munmaps  Change (K)  Rate (K/Sec)\n",
			pid_size, "PID");
		for (l = sorted.head; l; l = l->next) {
			info = (mem_mmap_info_t *)l->data;
			proc_info_t *p = proc_cache_find_by_pid(info->pid);
			int64_t delta = info->mmap_length - info->munmap_length;
			double rate = ((double)delta) / duration;

			printf(" %*d %-20.20s %8" PRIu64 " %8" PRIu64 "    %8" PRIi64 "      %8.2f (%s)\n",
				pid_size, info->pid,
				p ? p->cmdline : "",
				info->mmap_count, info->munmap_count,
				delta / 1024, rate / 1024.0, mem_loading(rate));
		}
		printf("\n");
	}

#ifdef JSON_OUTPUT
	if (j_tests) {
		json_object *j_mem_test, *j_mem_infos, *j_mem_info;
		uint64_t total_mmap_count = 0, total_munmap_count = 0, total_delta = 0;

		if ((j_mem_test = j_obj_new_obj()) == NULL)
			goto out;
		j_obj_obj_add(j_tests, "memory-usage-via-mmap", j_mem_test);
		if ((j_mem_infos = j_obj_new_array()) == NULL)
			goto out;
		j_obj_obj_add(j_mem_test, "memory-usage-via-mmap-per-process", j_mem_infos);
		for (l = sorted.head; l; l = l->next) {
			info = (mem_mmap_info_t *)l->data;
			proc_info_t *p = proc_cache_find_by_pid(info->pid);
			int64_t delta = info->mmap_length - info->munmap_length;

			if ((j_mem_info = j_obj_new_obj()) == NULL)
				goto out;
			j_obj_new_int32_add(j_mem_info, "pid", info->pid);
			if (p) {
				j_obj_new_int32_add(j_mem_info, "ppid", p->ppid);
				j_obj_new_int32_add(j_mem_info, "is-thread", p->is_thread);
				j_obj_new_string_add(j_mem_info, "name", p->cmdline);
			}
			j_obj_new_int64_add(j_mem_info, "mmap-count", info->mmap_count);
			j_obj_new_int64_add(j_mem_info, "munmap-count", info->munmap_count);
			j_obj_new_int64_add(j_mem_info, "mmap-total-Kbytes", (uint64_t)delta / 1024);
			j_obj_new_double_add(j_mem_info, "mmap-total-Kbytes-rate", ((double)delta / 1024.0) / duration );
			j_obj_array_add(j_mem_infos, j_mem_info);

			total_mmap_count += info->mmap_count;
			total_munmap_count += info->munmap_count;
			total_delta += delta;
		}

		if ((j_mem_info = j_obj_new_obj()) == NULL)
			goto out;
		j_obj_obj_add(j_mem_test, "memory-usage-via-mmap-total", j_mem_info);
		j_obj_new_int64_add(j_mem_info, "mmap-count-total", total_mmap_count);
		j_obj_new_int64_add(j_mem_info, "munmap-count-total", total_munmap_count);
		j_obj_new_int64_add(j_mem_info, "mmap-total-Kbytes", total_delta / 1024);
		j_obj_new_double_add(j_mem_info, "mmap-total-Kbytes-rate", ((double)total_delta / 1024.0) / duration);
	}
#endif

out:
	list_free(&sorted, NULL);
}

/*
 *  mem_brk_account()
 *	sys_brk memory accouting, used in syscall.c
 */
int mem_brk_account(const pid_t pid, const void *addr)
{
	link_t *l;

	mem_brk_info_t *info = NULL;

	if (!addr)
		return 0;

	for (l = mem_brk_info.head; l; l = l->next) {
		info = (mem_brk_info_t *)l->data;
		if (info->pid == pid) {
			info->brk_current = addr;
			info->brk_count++;
			return 0;
		}
	}

	if ((info = calloc(1, sizeof(*info))) == NULL) {
		health_check_out_of_memory("allocating memory tracking brk() information");
		return -1;
	}
	info->pid = pid;
	info->brk_start = addr;
	info->brk_current = addr;
	info->brk_count = 1;
	if (list_append(&mem_brk_info, info) == NULL) {
		free(info);
		return -1;
	}

	return 0;
}

/*
 *  mem_brk_cmp()
 *	list sorting based on total brk size
 */
static int mem_brk_cmp(const void *data1, const void *data2)
{
	const mem_brk_info_t *m1 = (const mem_brk_info_t *)data1;
	const mem_brk_info_t *m2 = (const mem_brk_info_t *)data2;

	const ptrdiff_t p1 = (const char *)m1->brk_current - (const char *)m1->brk_start;
	const ptrdiff_t p2 = (const char *)m2->brk_current - (const char *)m2->brk_start;

	return p2 - p1;
}

/*
 *  mem_dump_brk()
 *	dump brk heap changes
 */
void mem_dump_brk(json_object *j_tests, const double duration)
{
	list_t sorted;
	link_t *l;
	mem_brk_info_t *info;

#if !defined(JSON_OUTPUT)
	(void)j_tests;
#endif

	printf("Heap Change via brk():\n");
	list_init(&sorted);

	for (l = mem_brk_info.head; l; l = l->next) {
		info = (mem_brk_info_t *)l->data;
		if (list_add_ordered(&sorted, info, mem_brk_cmp) == NULL)
			goto out;
	}

	if (mem_brk_info.head == NULL) {
		printf(" None.\n\n");
	} else {
		const int pid_size = pid_max_digits();

		printf(" %*s                       brk Count   Change (K)  Rate (K/Sec)\n",
			pid_size, "PID");
		for (l = sorted.head; l; l = l->next) {
			info = (mem_brk_info_t *)l->data;
			const proc_info_t *p = proc_cache_find_by_pid(info->pid);
			const ptrdiff_t delta = ((const char *)info->brk_current - (const char *)info->brk_start);
			const double rate = ((double)delta) / duration;

			printf(" %*d %-20.20s   %8" PRIu64 " %12td      %8.2f (%s)\n",
				pid_size, info->pid,
				p ? p->cmdline : "", info->brk_count,
				delta / 1024,
				rate / 1024.0, mem_loading(rate));
		}
		printf("\n");
	}

#ifdef JSON_OUTPUT
	if (j_tests) {
		json_object *j_mem_test, *j_mem_infos, *j_mem_info;
		uint64_t total_brk_count = 0, total_delta = 0;

		if ((j_mem_test = j_obj_new_obj()) == NULL)
			goto out;
		j_obj_obj_add(j_tests, "heap-usage-via-brk", j_mem_test);
		if ((j_mem_infos = j_obj_new_array()) == NULL)
			goto out;
		j_obj_obj_add(j_mem_test, "heap-usage-via-brk-per-process", j_mem_infos);
		for (l = sorted.head; l; l = l->next) {
			info = (mem_brk_info_t *)l->data;
			const proc_info_t *p = proc_cache_find_by_pid(info->pid);
			const ptrdiff_t delta = ((const char *)info->brk_current - (const char *)info->brk_start);

			if ((j_mem_info = j_obj_new_obj()) == NULL)
				goto out;
			j_obj_new_int32_add(j_mem_info, "pid", info->pid);
			if (p) {
				j_obj_new_int32_add(j_mem_info, "ppid", p->ppid);
				j_obj_new_int32_add(j_mem_info, "is-thread", p->is_thread);
				j_obj_new_string_add(j_mem_info, "name", p->cmdline);
			}
			j_obj_new_int64_add(j_mem_info, "brk-count", info->brk_count);
			j_obj_new_int64_add(j_mem_info, "brk-size-Kbytes", (uint64_t)delta / 1024);
			j_obj_new_double_add(j_mem_info, "brk-size-Kbytes-rate", ((double)delta / 1024.0) / duration);
			j_obj_array_add(j_mem_infos, j_mem_info);

			total_brk_count += info->brk_count;
			total_delta += (uint64_t)delta;
		}
		if ((j_mem_info = j_obj_new_obj()) == NULL)
			goto out;
		j_obj_obj_add(j_mem_test, "heap-usage-via-brk-total", j_mem_info);
		j_obj_new_int64_add(j_mem_info, "brk-count-total", total_brk_count);
		j_obj_new_int64_add(j_mem_info, "brk-size-total-Kbytes", total_delta / 1024);
		j_obj_new_double_add(j_mem_info, "brk-size-total-Kbytes-rate", ((double)total_delta / 1024.0) / duration);
	}
#endif

out:
	list_free(&sorted, NULL);
}

/*
 *  mem_cmp()
 *	list sorting based on total memory used
 */
static int mem_cmp(const void *data1, const void *data2)
{
	const mem_info_t *m1 = (const mem_info_t *)data1;
	const mem_info_t *m2 = (const mem_info_t *)data2;

	return m2->grand_total - m1->grand_total;
}

/*
 *  mem_get_size()
 *	parse proc sizes in K bytes
 */
static int mem_get_size(FILE *fp, const char *field, uint64_t *size)
{
	char tmp[4096];
	uint64_t size_k;

	*size = 0;

	while (!feof(fp)) {
		if (fscanf(fp, "%4095[^:]: %" SCNi64 "%*[^\n]%*c", tmp, &size_k) == 2) {
			if (strcmp(tmp, field) == 0) {
				*size = size_k * 1024;
				return 0;
			}
		}
	}
	return -1;
}

/*
 *  mem_get_entry()
 *	parse a single memory mapping entry
 */
static int mem_get_entry(FILE *fp, mem_info_t *mem)
{
	uint64_t addr_start, addr_end, addr_offset;
	int major, minor;
	mem_type_t type;
	char path[PATH_MAX];
	uint64_t size, rss, pss;

	for (;;) {
		char buffer[4096];

		if (fgets(buffer, sizeof(buffer), fp) == NULL)
			return -1;
		if (sscanf(buffer, "%" SCNx64 "-%" SCNx64 " %*s %" SCNx64 " %x:%x %*u %s",
			&addr_start, &addr_end, &addr_offset, &major, &minor, path) == 6)
			break;
		if (sscanf(buffer, "%" SCNx64 "-%" SCNx64 " %*s %" SCNx64 " %x:%x %*u",
			&addr_start, &addr_end, &addr_offset, &major, &minor) == 5) {
			*path = '\0';
			break;
		}
	}


	if (strncmp(path, "[stack", 6) == 0)
		type = MEM_STACK;
	else if (strncmp(path, "[heap", 5) == 0)
		type = MEM_HEAP;
	else if (!*path && addr_offset == 0 && major == 0 && minor == 0)
		type = MEM_HEAP;
	else
		type = MEM_MAPPED;

	if (mem_get_size(fp, "Size", &size) < 0)
		return -1;
	if (mem_get_size(fp, "Rss", &rss) < 0)
		return -1;
	if (mem_get_size(fp, "Pss", &pss) < 0)
		return -1;

	mem->size[type] += size;
	mem->rss[type] += rss;
	mem->pss[type] += pss;
	mem->total[type] += size + rss + pss;
	return 0;
}

/*
 *  mem_get_by_proc()
 *	get mem info for a specific proc
 */
int mem_get_by_proc(proc_info_t *p, const proc_state state)
{
	FILE *fp;
	char path[PATH_MAX];
	mem_info_t *m;
	list_t *mem = (state == PROC_START) ? &mem_info_old : &mem_info_new;

	if (p->is_thread)
		return 0;

	snprintf(path, sizeof(path), "/proc/%i/smaps", p->pid);

	if ((fp = fopen(path, "r")) == NULL)
		return 0;

	if ((m = calloc(1, sizeof(*m))) == NULL) {
		health_check_out_of_memory("allocating memory tracking information");
		(void)fclose(fp);
		return -1;
	}
	m->proc = p;

	while (mem_get_entry(fp, m) != -1)
		;

	if (list_append(mem, m) == NULL) {
		free(m);
		(void)fclose(fp);
		return -1;
	}
	(void)fclose(fp);

	return 0;
}

/*
 *  mem_get_all_pids()
 *	scan mem and get mmap info
 */
int mem_get_all_pids(const list_t *pids, const proc_state state)
{
	link_t *l;

	for (l = pids->head; l; l = l->next) {
		proc_info_t *p = (proc_info_t *)l->data;
		if (mem_get_by_proc(p, state) < 0) {
			return -1;
		}
	}
	return 0;
}

/*
 *  mem_delta()
 *	compute memory size change
 */
static mem_info_t *mem_delta(mem_info_t *mem_new, const list_t *mem_old_list)
{
	link_t *l;
	int i;
	mem_info_t *delta;

	if ((delta = calloc(1, sizeof(*delta))) == NULL) {
		health_check_out_of_memory("allocating memory delta tracking information");
		return NULL;
	}

	memset(delta, 0, sizeof(*delta));

	for (l = mem_old_list->head; l; l = l->next) {
		mem_info_t *mem_old = (mem_info_t *)l->data;
		if (mem_new->proc == mem_old->proc) {
			for (i = 0; i < MEM_MAX; i++) {
				delta->proc = mem_new->proc;
				delta->size[i] = mem_new->size[i] - mem_old->size[i];
				delta->rss[i] = mem_new->rss[i] - mem_old->rss[i];
				delta->pss[i] = mem_new->pss[i] - mem_old->pss[i];
				delta->total[i] = mem_new->total[i] - mem_old->total[i];
			}
			return delta;
		}
	}
	/* Old not found, return new */
	memcpy(delta, mem_new, sizeof(*delta));
	return delta;
}

/*
 *  mem_dump_diff()
 *	dump differences between old and new events
 */
int mem_dump_diff(
	json_object *j_tests,
	const double duration)
{
	list_t sorted, sorted_delta;
	link_t *l;
	bool deltas = false;

#ifndef JSON_OUTPUT
	(void)j_tests;
#endif

	printf("Memory:\n");

	list_init(&sorted);
	list_init(&sorted_delta);

	for (l = mem_info_new.head; l; l = l->next) {
		mem_type_t type;
		mem_info_t *mem_new = (mem_info_t *)l->data;

		for (type = MEM_STACK; type < MEM_MAX; type++)
			mem_new->grand_total += mem_new->total[type];

		if (list_add_ordered(&sorted, mem_new, mem_cmp) == NULL)
			goto out;
	}

	for (l = mem_info_new.head; l; l = l->next) {
		mem_info_t *delta, *mem_new = (mem_info_t *)l->data;

		if ((delta = mem_delta(mem_new, &mem_info_old)) == NULL)
			return -1;
		if (list_add_ordered(&sorted_delta, delta, mem_cmp) == NULL) {
			free(delta);
			goto out;
		}
	}

	if (!(opt_flags & OPT_BRIEF)) {
		printf("Per Process Memory (K):\n");
		if (mem_info_new.head == NULL) {
			printf(" No memory detected.\n\n");
		} else {
			const int pid_size = pid_max_digits();

			printf(" %*s Process              Type        Size       RSS       PSS\n",
				pid_size, "PID");
			for (l = sorted.head; l; l = l->next) {
				mem_info_t *delta = (mem_info_t *)l->data;
				mem_type_t type;

				for (type = MEM_STACK; type < MEM_MAX; type++) {
					printf(" %*d %-20.20s %-6.6s %9" PRIi64 " %9" PRIi64 " %9" PRIi64 "\n",
						pid_size, delta->proc->pid,
						delta->proc->cmdline,
						mem_types[type],
						delta->size[type] / 1024,
						delta->rss[type] / 1024,
						delta->pss[type] / 1024);
				}
			}
			printf("\n");
		}
	}

	printf("Change in memory (K/second):\n");
	if (mem_info_new.head == NULL) {
		printf(" No memory detected.\n\n");
	} else {
		const int pid_size = pid_max_digits();

		for (l = sorted_delta.head; l; l = l->next) {
			mem_info_t *delta = (mem_info_t *)l->data;
			mem_type_t type;

			for (type = MEM_STACK; type < MEM_MAX; type++) {
				if (delta->total[type]) {
					if (!deltas) {
						printf(" %*s Process              Type        Size       RSS       PSS\n",
							pid_size, "PID");
						deltas = true;
					}
					printf(" %*d %-20.20s %-6.6s %9.2f %9.2f %9.2f (%s)\n",
						pid_size, delta->proc->pid,
						delta->proc->cmdline,
						mem_types[type],
						(double)(delta->size[type] / 1024.0) / duration,
						(double)(delta->rss[type] / 1024.0) / duration,
						(double)(delta->pss[type] / 1024.0) / duration,
						mem_loading((double)(delta->total[type] / duration)));
				}
			}
		}
	}
	if (!deltas)
		printf(" No changes found.\n");
	printf("\n");

#ifdef JSON_OUTPUT
	if (j_tests) {
		json_object *j_mem_test, *j_mem_infos, *j_mem_info;
		char label[128];
		mem_type_t type;
		double rate;
		int64_t total_size[MEM_MAX], total_rss[MEM_MAX], total_pss[MEM_MAX];

		memset(total_size, 0, sizeof(total_size));
		memset(total_rss, 0, sizeof(total_rss));
		memset(total_pss, 0, sizeof(total_pss));

		if ((j_mem_test = j_obj_new_obj()) == NULL)
			goto out;
		j_obj_obj_add(j_tests, "memory-usage", j_mem_test);
		if ((j_mem_infos = j_obj_new_array()) == NULL)
			goto out;
		j_obj_obj_add(j_mem_test, "memory-usage-per-process", j_mem_infos);
		for (l = sorted.head; l; l = l->next) {
			mem_info_t *delta = (mem_info_t *)l->data;

			for (type = MEM_STACK; type < MEM_MAX; type++) {
				if ((j_mem_info = j_obj_new_obj()) == NULL)
					goto out;
				j_obj_new_int32_add(j_mem_info, "pid", delta->proc->pid);
				j_obj_new_int32_add(j_mem_info, "ppid", delta->proc->ppid);
				j_obj_new_int32_add(j_mem_info, "is-thread", delta->proc->is_thread);
				j_obj_new_string_add(j_mem_info, "name", delta->proc->cmdline);
				/* Size */
				snprintf(label, sizeof(label), "%s-size-Kbytes", mem_types[type]);
				mem_tolower_str(label);
				j_obj_new_int64_add(j_mem_info, label, delta->size[type] / 1024);
				/* RSS */
				snprintf(label, sizeof(label), "%s-rss-Kbytes", mem_types[type]);
				mem_tolower_str(label);
				j_obj_new_int64_add(j_mem_info, label, delta->rss[type] / 1024);
				/* PSS */
				snprintf(label, sizeof(label), "%s-pss-Kbytes", mem_types[type]);
				mem_tolower_str(label);
				j_obj_new_int64_add(j_mem_info, label, delta->pss[type] / 1024);

				j_obj_array_add(j_mem_infos, j_mem_info);

				total_size[type] += delta->size[type];
				total_rss[type] += delta->rss[type];
				total_pss[type] += delta->pss[type];
			}
		}
		if ((j_mem_info = j_obj_new_obj()) == NULL)
			goto out;
		j_obj_obj_add(j_mem_test, "memory-usage-total", j_mem_info);
		for (type = MEM_STACK; type < MEM_MAX; type++) {
			/* Size */
			snprintf(label, sizeof(label), "%s-size-total-Kbytes", mem_types[type]);
			mem_tolower_str(label);
			j_obj_new_int64_add(j_mem_info, label, total_size[type] / 1024);
			/* RSS */
			snprintf(label, sizeof(label), "%s-rss-total-Kbytes", mem_types[type]);
			mem_tolower_str(label);
			j_obj_new_int64_add(j_mem_info, label, total_rss[type] / 1024);
			/* PSS */
			snprintf(label, sizeof(label), "%s-pss-total-Kbytes", mem_types[type]);
			mem_tolower_str(label);
			j_obj_new_int64_add(j_mem_info, label, total_pss[type] / 1024);
		}

		memset(total_size, 0, sizeof(total_size));
		memset(total_rss, 0, sizeof(total_rss));
		memset(total_pss, 0, sizeof(total_pss));

		if ((j_mem_test = j_obj_new_obj()) == NULL)
			goto out;
		j_obj_obj_add(j_tests, "memory-change", j_mem_test);
		if ((j_mem_infos = j_obj_new_array()) == NULL)
			goto out;
		j_obj_obj_add(j_mem_test, "memory-change-per-process", j_mem_infos);
		for (l = sorted_delta.head; l; l = l->next) {
			mem_info_t *delta = (mem_info_t *)l->data;

			for (type = MEM_STACK; type < MEM_MAX; type++) {
				if ((j_mem_info = j_obj_new_obj()) == NULL)
					goto out;
				j_obj_new_int32_add(j_mem_info, "pid", delta->proc->pid);
				j_obj_new_int32_add(j_mem_info, "ppid", delta->proc->ppid);
				j_obj_new_int32_add(j_mem_info, "is-thread", delta->proc->is_thread);
				j_obj_new_string_add(j_mem_info, "name", delta->proc->cmdline);
				/* Size */
				rate = (double)(delta->size[type] / 1024.0) / duration;
				snprintf(label, sizeof(label), "%s-change-size-Kbytes", mem_types[type]);
				mem_tolower_str(label);
				j_obj_new_int64_add(j_mem_info, label, delta->size[type] / 1024);
				snprintf(label, sizeof(label), "%s-change-size-Kbytes-rate", mem_types[type]);
				mem_tolower_str(label);
				j_obj_new_double_add(j_mem_info, label, rate);
				snprintf(label, sizeof(label), "%s-change-size-Kbytes-hint", mem_types[type]);
				mem_tolower_str(label);
				j_obj_new_string_add(j_mem_info, label, mem_loading(rate));
				/* RSS */
				rate = (double)(delta->rss[type] / 1024.0) / duration;
				snprintf(label, sizeof(label), "%s-change-rss-Kbytes", mem_types[type]);
				mem_tolower_str(label);
				j_obj_new_int64_add(j_mem_info, label, delta->rss[type] / 1024);
				snprintf(label, sizeof(label), "%s-change-rss-Kbytes-rate", mem_types[type]);
				mem_tolower_str(label);
				j_obj_new_double_add(j_mem_info, label, rate);
				snprintf(label, sizeof(label), "%s-change-rss-Kbytes-hint", mem_types[type]);
				mem_tolower_str(label);
				j_obj_new_string_add(j_mem_info, label, mem_loading(rate));
				/* PSS */
				rate = (double)(delta->pss[type] / 1024.0) / duration;
				snprintf(label, sizeof(label), "%s-change-pss-Kbytes", mem_types[type]);
				mem_tolower_str(label);
				j_obj_new_int64_add(j_mem_info, label, delta->pss[type] / 1024);
				snprintf(label, sizeof(label), "%s-change-pss-Kbytes-rate", mem_types[type]);
				mem_tolower_str(label);
				j_obj_new_double_add(j_mem_info, label, rate);
				snprintf(label, sizeof(label), "%s-change-pss-Kbytes-hint", mem_types[type]);
				mem_tolower_str(label);
				j_obj_new_string_add(j_mem_info, label, mem_loading(rate));

				j_obj_array_add(j_mem_infos, j_mem_info);

				total_size[type] += delta->size[type];
				total_rss[type] += delta->rss[type];
				total_pss[type] += delta->pss[type];
			}
		}
		if ((j_mem_info = j_obj_new_obj()) == NULL)
			goto out;
		j_obj_obj_add(j_mem_test, "memory-change-total", j_mem_info);
		for (type = MEM_STACK; type < MEM_MAX; type++) {
			/* Size */
			snprintf(label, sizeof(label), "%s-change-size-total-Kbytes", mem_types[type]);
			mem_tolower_str(label);
			j_obj_new_int64_add(j_mem_info, label, total_size[type] / 1024);
			/* RSS */
			snprintf(label, sizeof(label), "%s-change-rss-total-Kbytes", mem_types[type]);
			mem_tolower_str(label);
			j_obj_new_int64_add(j_mem_info, label, total_rss[type] / 1024);
			/* PSS */
			snprintf(label, sizeof(label), "%s-change-pss-total-Kbytes", mem_types[type]);
			mem_tolower_str(label);
			j_obj_new_int64_add(j_mem_info, label, total_pss[type] / 1024);
		}
	}
#endif

out:
	list_free(&sorted, NULL);
	list_free(&sorted_delta, free);

	return 0;
}

/*
 *  mem_init()
 *	initialise mem lists
 */
void mem_init(void)
{
	list_init(&mem_info_old);
        list_init(&mem_info_new);
	list_init(&mem_brk_info);
	list_init(&mem_mmap_info);
}

/*
 *  mem_cleanup()
 *	free mem lists
 */
void mem_cleanup(void)
{
	list_free(&mem_info_old, free);
	list_free(&mem_info_new, free);
	list_free(&mem_brk_info, free);
	list_free(&mem_mmap_info, free);
}
