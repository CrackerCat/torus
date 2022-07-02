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

#include "parse.h"


/*
    *    src/parse.c
    *    Date: 06/27/22
    *    Author: @xmmword
*/


/**
 * @brief Parses physical address ranges.
 * @returns Returns a struct containing the physical address ranges.
 */

address_t *parse_physical_ranges(void) {
  uint32_t index = 0;
  uint8_t buffer[BUFSIZ] = {0};

  static address_t addresses[10] = {0};
  FILE *descriptor = fopen("/proc/iomem", "r");
  
  if (!descriptor)
    return NULL;
  
  while (fgets(buffer, sizeof(buffer), descriptor)) {
    if (index != 10 && !strstr(buffer, "Kernel "))
      continue;
    
    if (sscanf(buffer, "%lx-%lx", &addresses[index].addr_start, &addresses[index].addr_end))
      index++;
  }

  fclose(descriptor);
  return addresses;
}

/**
 * @brief Resolves the location of System.map.
 * @param symbol The symbol that will be looked up.
 * @param system_map The location of System.map.
 * @returns The address of the symbol, 0 if otherwise.
 */

uintptr_t parse_system_map_address(const uint8_t *symbol, const uint8_t *system_map) {
  uint8_t buffer[BUFSIZ] = {0};
  static syscall_t function = {0};

  FILE *descriptor = fopen(system_map, "r");
  if (!descriptor)
    return 0;

  while (fgets(buffer, sizeof(buffer), descriptor)) {
    if (!sscanf(buffer, "%lx %c %s", &function.address, &function.type, function.symbol))
      continue;

    if (!strncmp(function.symbol, symbol, strlen(function.symbol)))
      break;
  }

  fclose(descriptor);
  return function.address;
}