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
#ifndef __ALLOC_H__
#define __ALLOC_H__

#include <stdlib.h>
#include <stdio.h>

#if DEBUG_MALLOC

void *__malloc(const size_t size, const char *where, const int line);
void __free(void *ptr, const char *where, const int line);
void *__calloc(const size_t nmemb, const size_t size, const char *where, const int line);
void *__realloc(void *ptr, const size_t size, const char *where, const int line);

#define malloc(size)	__malloc(size, __func__, __LINE__)
#define free(ptr)	__free(ptr, __func__, __LINE__)
#define calloc(nmemb, size)	__calloc(nmemb, size, __func__, __LINE__)
#define realloc(ptr, size)	__realloc(ptr, size, __func__, __LINE__)

#endif

#endif
