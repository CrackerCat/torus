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

#include "elf.h"


/*
    *    src/elf.c
    *    Date: 07/02/22
    *    Author: @xmmword
*/


/**
 * @brief Reads the ELF header.
 * @param descriptor The file descriptor.
 * @returns The parsed ELF header.
 */

Elf64_Ehdr *read_elf_header(const int32_t descriptor) {
  static Elf64_Ehdr header = {0};

  return ((read(descriptor, &header, sizeof(header)) == -1) ? NULL : &header);
}

/**
 * @brief Parses the ELF program header.
 * @param header The ELF header.
 * @param descriptor The file descriptor.
 * @returns The parsed ELF program header.
 */

Elf64_Phdr *parse_elf_program_headers(const Elf64_Ehdr *header, const int32_t descriptor) {
  Elf64_Phdr *program_header = {0};

  if (lseek64(descriptor, header->e_phoff, SEEK_SET) == -1)
    return NULL;

  if (!(program_header = (Elf64_Phdr *)malloc((header->e_phnum * header->e_phentsize))) || read(descriptor, (void *)program_header, (header->e_phnum * header->e_phentsize)) == -1)
    return NULL;

  return program_header;
}