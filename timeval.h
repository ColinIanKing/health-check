/*
 * Copyright (C) 2013-2014 Canonical
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
#ifndef __TIMEVAL_H__
#define __TIMEVAL_H__

#define _GNU_SOURCE

#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

extern double timeval_double(const struct timeval *tv);
extern double timeval_to_double(const struct timeval *tv);
extern struct timeval timeval_add(const struct timeval *a, const struct timeval *b);
extern struct timeval timeval_sub(const struct timeval *a, const struct timeval *b);

#endif
