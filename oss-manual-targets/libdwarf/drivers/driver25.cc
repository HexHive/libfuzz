/* Copyright 2021 Google LLC
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
      http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
#include "dwarf.h"
#include "libdwarf.h"
#include <fcntl.h> /* open() O_RDONLY O_BINARY */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef O_BINARY
#define O_BINARY 0
#endif

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  char filename[256];
  sprintf(filename, "/tmp/libfuzzer.%d", getpid());

  FILE *fp = fopen(filename, "wb");
  if (!fp) {
    return 0;
  }
  fwrite(data, size, 1, fp);
  fclose(fp);

  Dwarf_Debug dbg = 0;
  int fuzz_fd = 0;
  int res = DW_DLV_ERROR;
  Dwarf_Error error = 0;
  Dwarf_Handler errhand = 0;
  Dwarf_Ptr errarg = 0;
  Dwarf_Error *errp = 0;
  int i = 0;
  Dwarf_Die die;

  fuzz_fd = open(filename, O_RDONLY|O_BINARY);
  if (fuzz_fd != -1) {
    res =
        dwarf_init_b(fuzz_fd, DW_GROUPNUMBER_ANY, errhand, errarg, &dbg, errp);
    if (res == DW_DLV_OK) {
      Dwarf_Xu_Index_Header xuhdr = 0;
      Dwarf_Unsigned version_number = 0;
      Dwarf_Unsigned offsets_count = 0;
      Dwarf_Unsigned units_count = 0;
      Dwarf_Unsigned hash_slots_count = 0;
      const char *section_name = 0;
      res = dwarf_get_xu_index_header(dbg, "cu", &xuhdr, &version_number,
                                      &offsets_count, &units_count,
                                      &hash_slots_count, &section_name, errp);
    }
  }
  dwarf_finish(dbg);
  close(fuzz_fd);
  unlink(filename);
  return 0;
}
