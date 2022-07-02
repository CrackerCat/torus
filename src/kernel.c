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
#include "parse.h"
#include "utils.h"
#include "kernel.h"


/*
    *    src/kernel.c
    *    Date: 07/02/22
    *    Author: @xmmword
*/


/**
 * @brief Returns a file offset from a static kernel address.
 * @param address The static kernel address.
 * @returns The file offset.
 */

static inline __attribute__((always_inline)) uintptr_t return_file_offset(const uintptr_t address) {
  return ((address - 0xffffffff80000000) - 0xe00000);
}

/**
 * @brief Dumps the data at the given segment and searches for the signature.
 * @param descriptor The file descriptor.
 * @param signature The sequence of bytes that will be searched for.
 * @param program_header The ELF program header.
 * @returns An address that contains the signature, 0 if otherwise.
 */

uintptr_t dump_kernel_segment(const int32_t descriptor, const uint8_t *signature, const Elf64_Phdr program_header) {
  ssize_t total_bytes, read_bytes;
  uintptr_t address = 0, offset = program_header.p_offset;

  uint8_t *buffer = (uint8_t *)malloc(0x100000);
  size_t data, dumped_data = program_header.p_memsz;

  if (!buffer || lseek64(descriptor, program_header.p_offset, SEEK_SET) == -1)
    return 0;

  while (dumped_data) {
    if (dumped_data > 0x100000)
      data = 0x100000;
    else
      data = dumped_data;
    
    if ((read_bytes = read(descriptor, buffer, data)) == -1)
      break;

    for (int32_t i = 0; i < read_bytes; i++) {
      if (!memcmp((buffer + i), signature, sizeof(signature))) {
        address = (offset + i);
        break;
      }
    }

    dumped_data -= read_bytes, offset += read_bytes;
  }

  free(buffer);
  return address;
}

/**
 * @brief Searches for a segment containing any of the parsed physical addresses within /proc/kcore.
 * @param descriptor The file descriptor.
 * @param header The ELF header.
 * @param program_header The ELF program header.
 * @param addresses The struct containing the physical address ranges.
 * @param signature The sequence of bytes that will be searched for.
 * @returns An address that contains the signature, 0 if otherwise.
 */

uintptr_t find_physical_segment(const int32_t descriptor, const Elf64_Ehdr *header, const Elf64_Phdr program_header, const address_t *addresses, const uint8_t *signature) {
  for (uint32_t k = 0; k < 10; ++k) {
    if (addresses[k].addr_start && (program_header.p_paddr == addresses[k].addr_start)) {
      const uintptr_t address = dump_kernel_segment(descriptor, signature, program_header);

      if (address)
        return address;
    }
  }

  return 0;
}

/**
 * @brief Parses /proc/kcore, dumps specific segments, and performs a signature scan on the dumped bytes.
 * @param signature The sequence of bytes that will be searched for.
 * @param addresses The struct containing the physical address ranges.
 * @returns An address that contains the signature, 0 if otherwise.
 */

uintptr_t kcore_signature_scan(const uint8_t *signature, const address_t *addresses) {
  uintptr_t temp = 0, address = 0;
  
  Elf64_Ehdr *header = {0};
  Elf64_Phdr *program_header = {0};

  int32_t descriptor = open64("/proc/kcore", O_RDONLY | O_LARGEFILE);
  if (descriptor == -1)
    return 0;

  if (!(header = read_elf_header(descriptor)))
    return 0;

  if (!(program_header = parse_elf_program_headers(header, descriptor)))
    return 0;

  for (uint32_t i = 0; i < header->e_phnum; ++i)
    if ((address = find_physical_segment(descriptor, header, program_header[i], addresses, signature)))
      break;

  close(descriptor);
  free(program_header);

  return address;
}


/**
 * @brief Disassembles and displays a comparison of the bytes.
 * @param symbol The symbol name. 
 * @param original_function The bytes of the original function.
 * @param modified_function The bytes of the modified function.
 */

#ifdef DEBUG
void disassemble_function_opcodes(const uint8_t *symbol, const uint8_t *original_function, const uint8_t *modified_function) {
  csh cs_handle = {0};
  cs_insn *modified_instructions = {0}, *original_instructions = {0};

  if (cs_open(CS_ARCH_X86, CS_MODE_64, &cs_handle) != CS_ERR_OK)
    return;

  size_t function_amount = cs_disasm(cs_handle, original_function, 30, 0x1000, 0, &original_instructions),
    modified_amount = cs_disasm(cs_handle, modified_function, (sizeof(modified_function) - 1), 0x1000, 0, &modified_instructions);

  if (function_amount < 0 && modified_amount < 0) {
    cs_close(&cs_handle);
    return;
  }

  printf("Disassembly of the [%s] in System.map:\n", symbol);
  
  for (size_t i = 0; i < function_amount; ++i)
    printf("\t%s\t\t%s\n", original_instructions[i].mnemonic, original_instructions[i].op_str);

  printf("Disassembly of [%s] in kernel virtual memory:\n", symbol);
  
  for (size_t i = 0; i < modified_amount; ++i)
    printf("\t%s\t\t%s\n", modified_instructions[i].mnemonic, modified_instructions[i].op_str);

  putchar('\n');

  cs_free(original_instructions, function_amount);
  cs_free(modified_instructions, modified_amount);
  cs_close(&cs_handle);
}
#endif

/**
 * @brief Searches for the function in kernel virtual memory, and reports it.
 * @param addresses A structure containing the parsed physical address range.
 * @param system_map The location of System.map.
 * @param vm_descriptor The file descriptor for the decompressed kernel image.
 * @param kcore_descriptor The file descriptor for /proc/kcore.
 * @param system_descriptor The file descriptor for System.map.
 * @param symbol The symbol.
 * @param results The amount of functions reported.
 */

void scan_executable_instructions(const address_t *addresses, const uint8_t *system_map, const int32_t vm_descriptor, 
                                  const int32_t kcore_descriptor, const int32_t system_descriptor, const uint8_t *symbol, uint32_t results) {
  
  uint8_t *modified_bytes = NULL, *original_bytes = dump_system_map_bytes(vm_descriptor, 300, return_file_offset(parse_system_map_address(symbol, system_map)) + 5);
  if (!original_bytes)
    return;

  const uintptr_t address = kcore_signature_scan(original_bytes, addresses);
  if (!address)
    return;

  if (!(modified_bytes = dump_kernel_address_bytes(kcore_descriptor, 300, (address - 5))))
    return;

  printf("Found [%s] at address [0x%lx]\n", symbol, address);
  ++results;

#ifdef DEBUG
  disassemble_function_opcodes(symbol, original_bytes, modified_bytes);
#endif

  free(modified_bytes);
  free(original_bytes);
}

/**
 * @brief Iterates over System.map entries.
 * @param system_map The location of System.map.
 * @param vm_descriptor The file descriptor for the decompressed kernel image.
 * @param kcore_descriptor The file descriptor for /proc/kcore.
 * @param system_descriptor The file descriptor for System.map.
 * @returns The amount of results.
 */

uint32_t iterate_system_map(const uint8_t *system_map, const int32_t vm_descriptor, const int32_t kcore_descriptor, const int32_t system_descriptor) {
  uint32_t results = 0;
  
  syscall_t entry = {0};
  uint8_t buffer[BUFSIZ] = {0};
  
  FILE *descriptor = fopen(system_map, "r");
  if (!descriptor)
    return 0;

  address_t *addresses = parse_physical_ranges();
  if (!addresses)
    return 0;

  while (fgets(buffer, sizeof(buffer), descriptor)) {
    if (!sscanf(buffer, "%lx %c %s", &entry.address, &entry.type, entry.symbol))
      continue;

    if (!strncmp(entry.symbol, "__x64_sys", 9) || !strncmp(entry.symbol, "__ia32", 6) || strstr(entry.symbol, "_eil_addr___ia32") || strstr(entry.symbol, "_eil_addr___x64"))
      scan_executable_instructions(addresses, system_map, vm_descriptor, kcore_descriptor, system_descriptor, entry.symbol, results);
  }

  fclose(descriptor);
  return results;
}

/**
 * @brief Handles the given command-line arguments.
 * @param vmlinuz The path to the decompressed linux kernel image.
 * @returns True if 'torus' was able to execute properly, false if otherwise.
 */

bool init_torus(const uint8_t *vmlinuz) {
  if (access(vmlinuz, F_OK) == -1 || !resolve_system_map())
    return false;

  const uint8_t *system_map = resolve_system_map();
  int32_t vm_descriptor = open(vmlinuz, O_RDONLY), system_descriptor = open(system_map, O_RDONLY), kcore_descriptor = open64("/proc/kcore", O_RDONLY | O_LARGEFILE);

  printf(
    "[vmlinuz] => %s\n"
    "[System.Map] => %s\n"
    "_text found at address [0x%lx]\n",
    vmlinuz,
    system_map,
    parse_system_map_address("_text", system_map)
  );

  printf("Scan has complete, kernel functions [%d] have been found!\n", iterate_system_map(system_map, vm_descriptor, kcore_descriptor, system_descriptor));

  close(vm_descriptor);
  close(kcore_descriptor);
  close(system_descriptor);

  return true;
}