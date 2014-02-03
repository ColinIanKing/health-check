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
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <json/json.h>

#include "json.h"
#include "health-check.h"

/*
 *  Older versions json-c don't int64
 */
extern json_object *json_object_new_int64(const int64_t) __attribute__((weak));

static inline void j_obj_is_null(json_object *obj, const char *msg)
{
	if (!obj)
		health_check_out_of_memory(msg);
}

json_object *j_obj_new_array(void)
{
	json_object *obj = json_object_new_array();

	j_obj_is_null(obj, "cannot allocate JSON array");
	return obj;
}

json_object *j_obj_new_obj(void)
{
	json_object *obj = json_object_new_object();

	j_obj_is_null(obj, "cannot allocate JSON object");
	return obj;
}

json_object *j_obj_new_int32(const int32_t i)
{
	json_object *obj = json_object_new_int(i);

	j_obj_is_null(obj, "cannot allocate JSON integer");
	return obj;
}

json_object *j_obj_new_int64(const int64_t i)
{
	json_object *obj = NULL;

	if (json_object_new_int64) {
		obj = json_object_new_int64(i);
	} else {
		/* Older json-c doesn't have int64, so convert to double */
		obj = json_object_new_double((double)i);
	}
	j_obj_is_null(obj, "cannot allocate JSON integer");
	return obj;
}

json_object *j_obj_new_double(const double d)
{
	json_object *obj = json_object_new_double(d);

	j_obj_is_null(obj, "cannot allocate JSON double");
	return obj;
}

json_object *j_obj_new_string(const char *str)
{
	json_object *obj = json_object_new_string(str);

	j_obj_is_null(obj, "cannot allocate JSON string");
	return obj;
}
