/*
 * Copyright (C) 2013-2017 Canonical, Ltd.
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

#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include "timeval.h"

/*
 *  timeval_to_double()
 *	convert timeval to seconds as a double
 */
double timeval_to_double(const struct timeval *tv)
{
	return (double)tv->tv_sec + ((double)tv->tv_usec / 1000000.0);
}

/*
 *  timeval_add()
 *	timeval a + b
 */
struct timeval timeval_add(const struct timeval *a, const struct timeval *b)
{
	struct timeval ret;

	ret.tv_sec = a->tv_sec + b->tv_sec;
	ret.tv_usec = a->tv_usec + b->tv_usec;
	if (ret.tv_usec > 1000000) {
		int nsec = (ret.tv_usec / 1000000);
		ret.tv_sec += nsec;
		ret.tv_usec -= (1000000 * nsec);
	}

	return ret;
}

/*
 *  timeval_sub()
 *	timeval a - b
 */
struct timeval timeval_sub(
	const struct timeval *a,
	const struct timeval *b)
{
	struct timeval ret, _b;

	_b.tv_sec = b->tv_sec;
	_b.tv_usec = b->tv_usec;

	if (a->tv_usec < _b.tv_usec) {
		int nsec = ((_b.tv_usec - a->tv_usec) / 1000000) + 1;
		_b.tv_sec += nsec;
		_b.tv_usec -= (1000000 * nsec);
	}
	if (a->tv_usec - _b.tv_usec > 1000000) {
		int nsec = (a->tv_usec - _b.tv_usec) / 1000000;
		_b.tv_sec -= nsec;
		_b.tv_usec += (1000000 * nsec);
	}

	ret.tv_sec = a->tv_sec - _b.tv_sec;
	ret.tv_usec = a->tv_usec - _b.tv_usec;

	return ret;
}
