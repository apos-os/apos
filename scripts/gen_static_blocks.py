#!/usr/bin/python3
# Copyright 2025 Andrew Oates.  All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import sys
import hashlib

from typing import List, Tuple

BLOCK_SIZE = 128

TMPL_PREFIX = """
#include "dev/static_block_dev.h"

// Pre-declarations (for a header file).
extern const stblk_data_single_t {var_prefix}_BlockData[{num_unique_blocks}];
{pre_decls}

const stblk_data_single_t {var_prefix}_BlockData[{num_unique_blocks}] = {{
  {formatted_block_data}
}};
"""

TMPL_BLOCK_MAP_PREDECLS = "extern const stblk_spec_t {var_prefix}_{fvar};"

TMPL_BLOCK_MAP = """

// Generated from {filename}
#define _{var_prefix}_{fvar}_BlockMapLen {block_map_len}
static const int {var_prefix}_{fvar}_BlockMap[_{var_prefix}_{fvar}_BlockMapLen] = {{
  {block_map_data}
}};
const stblk_spec_t {var_prefix}_{fvar} = {{
  .block_data = {var_prefix}_BlockData,
  .block_map = {var_prefix}_{fvar}_BlockMap,
  .total_blocks = {total_blocks},
  .block_map_len= _{var_prefix}_{fvar}_BlockMapLen,
}};
"""

def DoPrint(var_prefix: str, unique_blocks: List[str],
            files_data: Tuple[str, str, str]):
  # First generate the printed block maps data, and their pre-decls
  pre_decls = []
  block_maps_printed = []
  for filename, fvar, block_map in files_data:
    block_map_data = []
    for i, idx in enumerate(block_map):
      if idx is not None:
        block_map_data.append(i)
        block_map_data.append(idx)
    block_map_len = len(block_map_data)
    block_map_data = ', '.join([str(x) for x in block_map_data])
    block_maps_printed.append(TMPL_BLOCK_MAP.format(
      var_prefix=var_prefix,
      filename=filename,
      fvar=fvar,
      total_blocks=len(block_map),
      block_map_len=block_map_len,
      block_map_data=block_map_data
      ))
    pre_decls.append(TMPL_BLOCK_MAP_PREDECLS.format(
      var_prefix=var_prefix,
      fvar=fvar))

  # Generated and print the top of the file
  formatted_blocks = []
  for block in unique_blocks:
    cstr = ', '.join([format(b, '#04x') for b in block])
    formatted_blocks.append("  { { %s } }" % cstr)

  print(TMPL_PREFIX.format(var_prefix=var_prefix,
                           formatted_block_data=",\n".join(formatted_blocks),
                           num_unique_blocks=len(unique_blocks),
                           pre_decls='\n'.join(pre_decls)))
  print('\n'.join(block_maps_printed))


def main():
  static_args = 2
  if len(sys.argv) < static_args + 2  or (len(sys.argv) - static_args) % 2 != 0:
    print(f"Usage: {sys.argv[0]} <var_prefix> <name1> <filename1> [<name2> <filename2> ...]", file=sys.stderr)
    sys.exit(1)

  var_prefix = sys.argv[1]
  out_filename = sys.argv[2]
  files = []
  for i in range((len(sys.argv) - static_args) // 2):
    files.append((sys.argv[static_args + 2 * i],
                  sys.argv[static_args + 2 * i + 1]))

  unique_blocks = []
  hash_to_index = {}

  total_bytes_read = 0
  total_blocks_read = 0
  total_blocks_not_zero = 0

  files_out = []
  for var_name, filename in files:
    file_block_mapping = []
    file_total_blocks = 0
    try:
      with open(filename, 'rb') as f:
        while True:
          block = f.read(BLOCK_SIZE)
          if not block:
            break

          total_bytes_read += len(block)
          total_blocks_read += 1
          file_total_blocks += 1

          if len(block) < BLOCK_SIZE:
            block = block.ljust(BLOCK_SIZE, b'\x00')

          # Check if block is all zeros
          is_zero = True
          for b in block:
            if b != 0:
              is_zero = False
              break

          if is_zero:
            file_block_mapping.append(None)
            continue
          total_blocks_not_zero += 1

          h = hashlib.sha256(block).hexdigest()
          if h not in hash_to_index:
            hash_to_index[h] = len(unique_blocks)
            unique_blocks.append(block)

          file_block_mapping.append(hash_to_index[h])

    except FileNotFoundError:
      print(f"Error: File '{filename}' not found.", file=sys.stderr)
      sys.exit(1)

    files_out.append((filename, var_name, file_block_mapping))

  print("Unique Blocks (hashes):", file=sys.stderr)
  for i, h in enumerate(unique_blocks):
    print(f"{i}: {h}", file=sys.stderr)

  for filename, var_name, file_block_mapping in files_out:
    print(f"\nFile {filename} Non-Zero Blocks:", file=sys.stderr)
    for i, idx in enumerate(file_block_mapping):
      if idx is not None:
        print(f"File {filename} block {i} (offset {i * BLOCK_SIZE:x})-> Unique block {idx}", file=sys.stderr)

  print("\nStats:", file=sys.stderr)
  print(f"Total bytes read: {total_bytes_read}", file=sys.stderr)
  print(f"Total blocks read: {total_blocks_read}", file=sys.stderr)
  print(f"Total unique blocks: {len(unique_blocks)}", file=sys.stderr)
  print(f"Total non-zero blocks: {total_blocks_not_zero}", file=sys.stderr)

  # Print formatted as a C file.
  DoPrint(var_prefix, unique_blocks, files_out)

if __name__ == "__main__":
  main()
