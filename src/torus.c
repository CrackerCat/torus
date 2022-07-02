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

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include "kernel.h"


/*
    *    src/torus.c
    *    Date: 06/27/22
    *    Author: @xmmword
*/


/**
 * @brief The entry point for the 'torus' program.
 * @param argc The argument count.
 * @param argv The argument vector.
 * @returns EXIT_SUCCESS if the program executed properly, EXIT_FAILURE if otherwise.
 */

int32_t main(int32_t argc, int8_t **argv) {
  fprintf(stderr, "Usage: %s <path/to/vmlinuz>\n\n", argv[0]);

  if (argc < 2)
    return EXIT_FAILURE;

  return ((init_torus(argv[1]) > 0) ? EXIT_SUCCESS : EXIT_FAILURE);
}