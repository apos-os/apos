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
