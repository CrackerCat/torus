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

#include "utils.h"


/*
    *    src/utils.c
    *    Date: 06/27/22
    *    Author: @xmmword
*/


/**
 * @brief Dumps the bytes of a given array.
 * @param amount The amount of bytes to dump.
 * @param buffer The array.
 * @returns NULL if the location couldn't be resolved, returns the string if otherwise.
 */

void dump_bytes(const int32_t amount, const uint8_t *buffer) {
  for (uint32_t i = 0; i < strnlen(buffer, amount); ++i)
    if (buffer[i])
      printf("0x%02x ", buffer[i]);

  putchar('\n');
}

/**
 * @brief Resolves the location of System.map.
 * @returns NULL if the location couldn't be resolved, returns the string if otherwise.
 */

uint8_t *resolve_system_map(void) {
  struct dirent *dir = NULL;
  static uint8_t path[PATH_MAX] = {0};

  DIR *directory = opendir("/boot");
  if (!directory)
    return NULL;

  while ((dir = readdir(directory))) {
    if (strstr(dir->d_name, "System.map-")) {
      snprintf(path, sizeof(path), "/boot/%s", dir->d_name); break;
    }
  }

  closedir(directory);
  return path;
}