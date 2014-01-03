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
#ifndef __JSON_SHIM_H__
#define __JSON_SHIM_H__

#ifdef JSON_OUTPUT

#include <json/json.h>

extern json_object *j_obj_new_array(void);
extern json_object *j_obj_new_obj(void);
extern json_object *j_obj_new_int32(const int32_t i);
extern json_object *j_obj_new_int64(const int64_t i);
extern json_object *j_obj_new_double(const double d);
extern json_object *j_obj_new_string(const char *str);

static inline void j_obj_obj_add(json_object *parent, const char *label, json_object *obj)
{
	json_object_object_add(parent, label, obj);
}

static inline void j_obj_array_add(json_object *array, json_object *obj)
{
	json_object_array_add(array, obj);
}

static inline void j_obj_new_int32_add(json_object *parent, const char *label, const int32_t i)
{
	j_obj_obj_add(parent, label, j_obj_new_int32(i));
}

static inline void j_obj_new_int64_add(json_object *parent, const char *label, const int64_t i)
{
	j_obj_obj_add(parent, label, j_obj_new_int64(i));
}

static inline void j_obj_new_double_add(json_object *parent, const char *label, const double d)
{
	j_obj_obj_add(parent, label, j_obj_new_double(d));
}

static inline void j_obj_new_string_add(json_object *parent, const char *label, const char *str)
{
	j_obj_obj_add(parent, label, j_obj_new_string(str));
}

#else
#define json_object void
#endif

#endif
