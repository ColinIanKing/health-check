/*
 * Copyright (C) 2013-2021 Canonical, Ltd.
 * Copyright (C) 2021-2024 Colin Ian King
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
 * Author: Colin Ian King <colin.i.king@gmail.com>
 */
#define _GNU_SOURCE

#include <stdlib.h>
#include <stdio.h>
#include "list.h"

/*
 *  list_init()
 *	initialize list
 */
void list_init(list_t *list)
{
	list->head = NULL;
	list->tail = NULL;
	list->length = 0;
}

/*
 *  list_append()
 *	add a new item to end of the list
 */
link_t *list_append(list_t *list, void *data)
{
	link_t *link;

	if ((link = calloc(1, sizeof(link_t))) == NULL) {
		fprintf(stderr, "Cannot allocate list link.\n");
		return NULL;
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
link_t *list_add_ordered(
	list_t *list,
	void *new_data,
	const list_comp_t compare)
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
void list_free(
	list_t *list,
	const list_link_free_t freefunc)
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
