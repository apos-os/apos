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

import re
import sys


def write_if_changed(file_path: str, new_content: str) -> None:
  try:
    with open(file_path, 'r') as f:
      if f.read() == new_content:
        return  # Do nothing, preserving the old timestamp
  except (FileNotFoundError, IOError):
    # File doesn't exist or isn't readable; proceed to write
    pass

  with open(file_path, 'w') as f:
    f.write(new_content)


def read_build_config(file_path: str) -> dict[str, str]:
  """Reads a build config file (a series of key=value lines) into a dict"""
  result = {}
  with open(file_path) as f:
    for line in f:
      line = re.sub('#.*', '', line)
      line = line.strip()
      if not line:
        continue
      m = re.match(R"([a-zA-Z0-9_]+)\s*=\s*'(.*)'", line)
      if not m:
        print(f'Warning: unparseable config line "{line}"', file=sys.stderr)
        continue
      result[m.group(1)] = m.group(2)
    return result
