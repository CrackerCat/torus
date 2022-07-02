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

#ifndef __STRUCTS_H
#define __STRUCTS_H

#include <stdint.h>
#include <inttypes.h>


/*
    *    src/structs.h
    *    Date: 07/02/22
    *    Author: @xmmword
*/


/* Structure containing physical address ranges! */
typedef struct _address {
  uintptr_t addr_start, addr_end;
} address_t;

/* Structure containing system call entries! */
typedef struct _syscall {
  uintptr_t address;
  uint8_t type, symbol[512];
} syscall_t;

#endif