/*
 * Copyright (C) 2013-2014 Canonical, Ltd.
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
#include <stdlib.h>
#include <stdio.h>

#include "alloc.h"

#if DEBUG_MALLOC

void *__malloc(const size_t size, const char *where, const int line)
{
	void *ptr = malloc(size);

	printf("malloc(%zu) --> %p  @ %s %d\n",
		size, ptr, where, line);

	return ptr;
}

void __free(void *ptr, const char *where, const int line)
{
	printf("free(%p) @ %s %d\n",
		ptr, where, line);
}

void *__calloc(const size_t nmemb, const size_t size, const char *where, const int line)
{
	void *ptr = calloc(nmemb, size);

	printf("calloc(%zu, %zu) --> %p  @ %s %d\n",
		nmemb, size, ptr, where, line);

	return ptr;
}

void *__realloc(void *ptr, const size_t size, const char *where, const int line)
{
	void *new = realloc(ptr, size);

	printf("realloc(%p, %zu) --> %p  @ %s %d\n",
		ptr, size, new, where, line);

	return new;
}

#endif
