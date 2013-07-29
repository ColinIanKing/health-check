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

#include "list.h"
#include "mem.h"
#include "health-check.h"

/*
 *  mem_cmp()
 *	compare event info for sorting
 */
static int mem_cmp(const void *data1, const void *data2)
{
	mem_info_t *m1 = (mem_info_t *)data1;
	mem_info_t *m2 = (mem_info_t *)data2;

	if (m2->size == m1->size)
		return 0;
	else if (m2->size > m1->size)
		return 1;
	else 
		return 0;
}

/*
 *  mem_add()
 *	add memory stats
 */
static void mem_add(
	list_t *mem,		/* memory allocation list */
	proc_info_t *proc,	/* process info */
	const uint64_t size)	/* total size of heap */
{
	mem_info_t *m;

	if ((m = calloc(1, sizeof(mem_info_t))) == NULL) {
		fprintf(stderr, "Out of memory\n");
		health_check_exit(EXIT_FAILURE);
	}

	m->size  = size;
	m->proc  = proc;

	list_add_ordered(mem, m, mem_cmp);
}

/*
 *  mem_get()
 *	scan mem and get mmap and heap info
 */
void mem_get(const list_t *pids, list_t *mem)
{
	link_t *l;

	for (l = pids->head; l; l = l->next) {
		FILE *fp;
		char buf[4096];
		proc_info_t *p = (proc_info_t *)l->data;
		uint64_t total_size = 0;

		if (p->is_thread)
			continue;

		snprintf(buf, sizeof(buf), "/proc/%i/maps", p->pid);

		if ((fp = fopen(buf, "r")) == NULL)
			continue;

		while(fgets(buf, sizeof(buf), fp) != NULL) {
			uint64_t addr_start, addr_end, addr_offset;
			int inode;

			if (sscanf(buf, "%" SCNx64 "-%" SCNx64 " %*s %" SCNx64 " %*s %i",
				&addr_start, &addr_end, &addr_offset, &inode) == 4) {
				/* Heap or anonymous memmap'd region? */
				if (addr_offset == 0 && inode == 0)
					total_size += addr_end - addr_start;
			}
		}
		fclose(fp);
		mem_add(mem, p, total_size);
	}
}

/*
 *  mem_delta()
 *	find mem old mem info and compare to new
 */
static int64_t mem_delta(const mem_info_t *mem_info_new, const list_t *mem_old)
{
	link_t *l;

	for (l = mem_old->head; l; l = l->next) {
		mem_info_t *mem_info_old = (mem_info_t *)l->data;
		if (mem_info_old->proc == mem_info_new->proc)
			return mem_info_new->size - mem_info_old->size;
	}
	return mem_info_new->size;
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
		return "(no change)";

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

	sprintf(buffer, "(%s%s)", verb, adverb);

	return buffer;
}

/*
 *  mem_dump_diff()
 *	dump differences between old and new events
 */
void mem_dump_diff(
	const double duration,
	const list_t *mem_old,
	const list_t *mem_new)
{
	link_t *l;

	printf("Heap memory:\n");
	if (mem_new->head == NULL) {
		printf(" No heap memory detected\n\n");
		return;
	}

	int count = 0;
	double total = 0.0;

	if (opt_flags & OPT_BRIEF) {
		for (l = mem_new->head; l; l = l->next) {
			mem_info_t *mem_info_new = (mem_info_t *)l->data;
			int64_t delta = mem_delta(mem_info_new, mem_old);
			double mem_rate = (double)delta / duration;
			total += mem_rate;
		}
		printf(" Heap growth rate: %.2f K/sec %s\n",
			total / 1024.0, mem_loading(total));
	} else {
		printf("  PID  Process               Heap Change (K/sec)\n");
		for (l = mem_new->head; l; l = l->next) {
			mem_info_t *mem_info_new = (mem_info_t *)l->data;
			int64_t delta = mem_delta(mem_info_new, mem_old);
			double mem_rate = (double)delta / duration;

			printf(" %5d %-20.20s %9.2f %s\n",
				mem_info_new->proc->pid, mem_info_new->proc->cmdline,
				mem_rate / 1024.0, mem_loading(mem_rate));
			total += mem_rate;
			count++;
		}
		if (count > 1)
			printf(" %-27.27s%9.2f %s\n", "Total",
				total / 1024.0, mem_loading(total));
		printf("\n");
	}
}
