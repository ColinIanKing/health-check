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
#include <stdlib.h>
#include <stdio.h>

#if DEBUG_MALLOC

void *__malloc(size_t size, char *where, int line)
{
	void *ptr = malloc(size);

	printf("malloc(%zd) --> %p  @ %s %d\n",
		size, ptr, where, line);

	return ptr;
}

void __free(void *ptr, char *where, int line)
{
	printf("free(%p) @ %s %d\n",
		ptr, where, line);
}

void *__calloc(size_t nmemb, size_t size, char *where, int line)
{
	void *ptr = calloc(nmemb, size);

	printf("calloc(%zd, %zd) --> %p  @ %s %d\n",
		nmemb, size, ptr, where, line);

	return ptr;
}

void *__realloc(void *ptr, size_t size, char *where, int line)
{
	void *new = realloc(ptr, size);

	printf("realloc(%p, %zd) --> %p  @ %s %d\n",
		ptr, size, new, where, line);

	return new;
}

#endif