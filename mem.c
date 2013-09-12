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

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>

#include "list.h"
#include "mem.h"
#include "health-check.h"

static list_t mem_info_old, mem_info_new;

static const char *mem_types[] = {
	"Stack",
	"Heap",
	"Mapped",
};

/*
 *  mem_cmp()
 *	list sorting based on total memory used
 */
static int mem_cmp(const void *data1, const void *data2)
{
	mem_info_t *m1 = (mem_info_t *)data1;
	mem_info_t *m2 = (mem_info_t *)data2;

	if (m2->total == m1->total)
		return 0;
	else if (m2->total > m1->total)
		return 1;
	else 
		return 0;
}

/*
 *  mem_get_size()
 *	parse proc sizes in K bytes
 */
static int mem_get_size(FILE *fp, char *field, uint64_t *size)
{
	char tmp[4096];
	uint64_t size_k;

	*size = 0;

	while (!feof(fp)) {
		if (fscanf(fp, "%[^:]: %" SCNi64 "%*[^\n]%*c", tmp, &size_k) == 2) {
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
void mem_get_by_proc(proc_info_t *p, proc_state state)
{
	FILE *fp;
	char path[PATH_MAX];
	mem_info_t *m;
	list_t *mem = (state == PROC_START) ? &mem_info_old : &mem_info_new;

	if (p->is_thread)
		return;

	snprintf(path, sizeof(path), "/proc/%i/smaps", p->pid);

	if ((fp = fopen(path, "r")) == NULL)
		return;

	if ((m = calloc(1, sizeof(*m))) == NULL) {
		fprintf(stderr, "Out of memory\n");
		health_check_exit(EXIT_FAILURE);
	}
	m->proc = p;

	while (mem_get_entry(fp, m) != -1)
		;

	list_append(mem, m);
	fclose(fp);
}

/*
 *  mem_get_all_pids()
 *	scan mem and get mmap info
 */
void mem_get_all_pids(const list_t *pids, proc_state state)
{
	link_t *l;

	for (l = pids->head; l; l = l->next) {
		proc_info_t *p = (proc_info_t *)l->data;
		mem_get_by_proc(p, state);
	}
}

/*
 *  mem_loading()
 *	convert heath growth rate into human readable form
 */
static const char *mem_loading(const double mem_rate)
{
	char *verb, *adverb;
	static char buffer[64];
	double rate = mem_rate;

	if (rate == 0.0)
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
 *  mem_delta()
 *	compute memory size change
 */
static mem_info_t *mem_delta(mem_info_t *mem_new, const list_t *mem_old_list)
{
	link_t *l;
	int i;
	mem_info_t *delta;

	if ((delta = calloc(1, sizeof(*delta))) == NULL) {
		fprintf(stderr, "Out of memory\n");
		health_check_exit(EXIT_FAILURE);
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
void mem_dump_diff(
	json_object *j_tests,
	const double duration)
{
	list_t sorted, sorted_delta;
	link_t *l;
	bool deltas = false;

#ifndef JSON_OUTPUT
	(void)j_tests;
#endif

	if (mem_info_new.head == NULL) {
		printf("Memory:\n");
		printf(" No memory detected.\n\n");
		return;
	}

	list_init(&sorted);
	list_init(&sorted_delta);

	for (l = mem_info_new.head; l; l = l->next) {
		mem_info_t *mem_new = (mem_info_t *)l->data;
		list_add_ordered(&sorted, mem_new, mem_cmp);
	}

	for (l = mem_info_new.head; l; l = l->next) {
		mem_info_t *delta, *mem_new = (mem_info_t *)l->data;

		delta = mem_delta(mem_new, &mem_info_old);
		list_add_ordered(&sorted_delta, delta, mem_cmp);
	}

	if (!(opt_flags & OPT_BRIEF)) {
		printf("Per Process Memory (K):\n");
		printf("  PID  Process              Type        Size       RSS       PSS\n");
		for (l = sorted.head; l; l = l->next) {
			mem_info_t *delta = (mem_info_t *)l->data;
			mem_type_t type;

			for (type = MEM_STACK; type < MEM_MAX; type++) {
				printf(" %5d %-20.20s %-6.6s %9" PRIi64 " %9" PRIi64 " %9" PRIi64 "\n",
					delta->proc->pid, delta->proc->cmdline,
					mem_types[type],
					delta->size[type] / 1024,
					delta->rss[type] / 1024,
					delta->pss[type] / 1024);
			}
		}
		printf("\n");
	}

	printf("Change in memory (K/second):\n");
	for (l = sorted_delta.head; l; l = l->next) {
		mem_info_t *delta = (mem_info_t *)l->data;
		mem_type_t type;

		for (type = MEM_STACK; type < MEM_MAX; type++) {
			if (delta->total[type]) {
				if (!deltas) {
					printf("  PID  Process              Type        Size       RSS       PSS\n");
					deltas = true;
				}
				printf(" %5d %-20.20s %-6.6s %9.2f %9.2f %9.2f (%s)\n",
					delta->proc->pid, delta->proc->cmdline,
					mem_types[type],
					(double)(delta->size[type] / 1024.0) / duration,
					(double)(delta->rss[type] / 1024.0) / duration,
					(double)(delta->pss[type] / 1024.0) / duration,
					mem_loading((double)(delta->total[type] / duration)));
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

		j_obj_obj_add(j_tests, "memory-usage", (j_mem_test = j_obj_new_obj()));
		j_obj_obj_add(j_mem_test, "memory-usage-per-process", (j_mem_infos = j_obj_new_array()));
		for (l = sorted.head; l; l = l->next) {
			mem_info_t *delta = (mem_info_t *)l->data;

			for (type = MEM_STACK; type < MEM_MAX; type++) {
				j_mem_info = j_obj_new_obj();
				j_obj_new_int32_add(j_mem_info, "pid", delta->proc->pid);
				j_obj_new_int32_add(j_mem_info, "ppid", delta->proc->ppid);
				j_obj_new_int32_add(j_mem_info, "is-thread", delta->proc->is_thread);
				j_obj_new_string_add(j_mem_info, "name", delta->proc->cmdline);
				/* Size */
				snprintf(label, sizeof(label), "%s-size-Kbytes", mem_types[type]);
				j_obj_new_int64_add(j_mem_info, label, delta->size[type] / 1024);
				j_obj_array_add(j_mem_infos, j_mem_info);
				/* RSS */
				snprintf(label, sizeof(label), "%s-rss-Kbytes", mem_types[type]);
				j_obj_new_int64_add(j_mem_info, label, delta->rss[type] / 1024);
				j_obj_array_add(j_mem_infos, j_mem_info);
				/* PSS */
				snprintf(label, sizeof(label), "%s-pss-Kbytes", mem_types[type]);
				j_obj_new_int64_add(j_mem_info, label, delta->pss[type] / 1024);
				j_obj_array_add(j_mem_infos, j_mem_info);
			}
		}

		j_obj_obj_add(j_tests, "memory-change", (j_mem_test = j_obj_new_obj()));
		j_obj_obj_add(j_mem_test, "memory-change-per-process", (j_mem_infos = j_obj_new_array()));
		for (l = sorted_delta.head; l; l = l->next) {
			mem_info_t *delta = (mem_info_t *)l->data;

			for (type = MEM_STACK; type < MEM_MAX; type++) {
				j_mem_info = j_obj_new_obj();
				j_obj_new_int32_add(j_mem_info, "pid", delta->proc->pid);
				j_obj_new_int32_add(j_mem_info, "ppid", delta->proc->ppid);
				j_obj_new_int32_add(j_mem_info, "is-thread", delta->proc->is_thread);
				j_obj_new_string_add(j_mem_info, "name", delta->proc->cmdline);
				/* Size */
				rate = (double)(delta->size[type] / 1024.0) / duration;
				snprintf(label, sizeof(label), "%s-change-size-Kbytes", mem_types[type]);
				j_obj_new_int64_add(j_mem_info, label, delta->size[type] / 1024);
				snprintf(label, sizeof(label), "%s-change-size-Kbytes-rate", mem_types[type]);
				j_obj_new_double_add(j_mem_info, label, rate);
				snprintf(label, sizeof(label), "%s-change-size-Kbytes-hint", mem_types[type]);
				j_obj_new_string_add(j_mem_info, label, mem_loading(rate));
				j_obj_array_add(j_mem_infos, j_mem_info);
				/* RSS */
				rate = (double)(delta->rss[type] / 1024.0) / duration;
				snprintf(label, sizeof(label), "%s-change-rss-Kbytes", mem_types[type]);
				j_obj_new_int64_add(j_mem_info, label, delta->rss[type] / 1024);
				snprintf(label, sizeof(label), "%s-change-rss-Kbytes-rate", mem_types[type]);
				j_obj_new_double_add(j_mem_info, label, rate);
				snprintf(label, sizeof(label), "%s-change-rss-Kbytes-hint", mem_types[type]);
				j_obj_new_string_add(j_mem_info, label, mem_loading(rate));
				j_obj_array_add(j_mem_infos, j_mem_info);
				/* PSS */
				rate = (double)(delta->pss[type] / 1024.0) / duration;
				snprintf(label, sizeof(label), "%s-change-pss-Kbytes", mem_types[type]);
				j_obj_new_int64_add(j_mem_info, label, delta->pss[type] / 1024);
				snprintf(label, sizeof(label), "%s-change-pss-Kbytes-rate", mem_types[type]);
				j_obj_new_double_add(j_mem_info, label, rate);
				snprintf(label, sizeof(label), "%s-change-pss-Kbytes-hint", mem_types[type]);
				j_obj_new_string_add(j_mem_info, label, mem_loading(rate));
				j_obj_array_add(j_mem_infos, j_mem_info);
			}
		}
	}
#endif
}

/*
 *  mem_init()
 *	initialise mem lists
 */
void mem_init(void)
{
	list_init(&mem_info_old);
        list_init(&mem_info_new);
}

/*
 *  mem_cleanup()
 *	free mem lists
 */
void mem_cleanup(void)
{
	list_free(&mem_info_old, free);
	list_free(&mem_info_new, free);
}
