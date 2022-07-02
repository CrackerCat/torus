/*
 * Copyright (C) 2022 xmmword
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef __UTILS_H
#define __UTILS_H

#include <fcntl.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <limits.h>
#include <unistd.h>
#include <stdbool.h>
#include <inttypes.h>


/*
    *    src/utils.h
    *    Date: 07/02/22
    *    Author: @xmmword
*/


uint8_t *resolve_system_map(void);
uint8_t *dump_system_map_bytes(const int32_t descriptor, const size_t nbytes, const uintptr_t address);
uint8_t *dump_kernel_address_bytes(const int32_t descriptor, const size_t nbytes, const uintptr_t address);

#endif