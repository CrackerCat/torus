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

#define _LARGEFILE64_SOURCE
#define _FILE_OFFSET_BITS 64

#ifndef __KERNEL_H
#define __KERNEL_H

#include <elf.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <inttypes.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <capstone/capstone.h>
#include "structs.h"


/*
    *    src/kernel.h
    *    Date: 06/27/22
    *    Author: @xmmword
*/


static inline __attribute__((always_inline)) uintptr_t return_file_offset(const uintptr_t address);
static inline __attribute__((always_inline)) uintptr_t return_kernel_address(const uintptr_t offset);

bool init_torus(const uint8_t *vmlinuz);

uint8_t *dump_kernel_address_bytes(const int32_t descriptor, const size_t nbytes, const uintptr_t address);
uint8_t *dump_system_map_bytes(const int32_t descriptor, const size_t nbytes, const uintptr_t address);

uintptr_t kcore_signature_scan(const uint8_t *signature, const address_t *addresses);
uintptr_t dump_kernel_segment(const int32_t descriptor, const uint8_t *signature, const Elf64_Phdr program_header);
uintptr_t find_physical_segment(const int32_t descriptor, const Elf64_Ehdr *header, const Elf64_Phdr program_header, const address_t *addresses, const uint8_t *signature);

#endif