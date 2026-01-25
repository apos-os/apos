#!/usr/bin/env python3
# Copyright 2026 Andrew Oates.  All Rights Reserved.
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
#
# Does a basic key/value substitution using Python-style substition patterns.
# Usage:
#  config_gen.py <template> <outfile> [KEY=VALUE ...]

import sys

def write_if_changed(file_path, new_content):
  try:
    with open(file_path, 'r') as f:
      if f.read() == new_content:
        return  # Do nothing, preserving the old timestamp
  except (FileNotFoundError, IOError):
    # File doesn't exist or isn't readable; proceed to write
    pass

  with open(file_path, 'w') as f:
    f.write(new_content)

def main():
  if len(sys.argv) < 3:
    print("Usage: config_gen.py <template> <outfile> [KEY=VALUE ...]")
    sys.exit(1)

  template_file = sys.argv[1]
  out_file = sys.argv[2]

  data = {}
  for arg in sys.argv[3:]:
    if '=' in arg:
      key, value = arg.split('=', 1)
      # Try to convert to int if possible, as formatting might use %d
      try:
        data[key] = int(value)
      except ValueError:
        data[key] = value

  with open(template_file, 'r') as f:
    content = f.read()

  # Perform python string formatting
  try:
    formatted = content % data
  except KeyError as e:
    # Print to stderr
    print(f"Error: Missing key {e} for template {template_file}", file=sys.stderr)
    sys.exit(1)

  write_if_changed(out_file, formatted)

if __name__ == '__main__':
  main()
