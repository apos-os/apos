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

import subprocess
import sys
import os

# Hack up python path so we can import build_util.
from pathlib import Path
root_dir = Path(__file__).resolve().parent.parent.parent.parent.parent
sys.path.append(str(root_dir))

from util import build_util

def main():
  if len(sys.argv) != 6:
    print(
        f"Usage: {sys.argv[0]} <compiler> <source> <so_file> <license_template> <out_file>",
        file=sys.stderr)
    sys.exit(1)

  compiler = sys.argv[1]
  source_file = sys.argv[2]
  so_file = sys.argv[3]
  license_file = sys.argv[4]
  out_file = sys.argv[5]

  # Compile the shared library.
  cc_cmd = [compiler, '-o', so_file, '-shared', '-Wl,--hash-style=gnu', source_file]
  # TODO(aoates): remove these bogus log lines when no longer doing build
  # comparisons
  print('[0/1] ' + subprocess.list2cmdline(cc_cmd), file=sys.stderr)
  cc_proc = subprocess.run(cc_cmd, stderr=sys.stderr)
  if cc_proc.returncode != 0:
    sys.exit(cc_proc.returncode)

  # Run xxd -i to generate a C array embedding the .so binary.
  xxd_cmd = ['xxd', '-i', '-n', 'kGnuHashLibRaw', so_file]
  print('[0/1] ' + subprocess.list2cmdline(xxd_cmd), file=sys.stderr)
  xxd_proc = subprocess.run(xxd_cmd, capture_output=True)

  if xxd_proc.returncode != 0:
    sys.stderr.buffer.write(xxd_proc.stderr)
    sys.exit(xxd_proc.returncode)

  formatted_output = xxd_proc.stdout.decode('utf-8')

  with open(license_file, "r") as f:
    license_content = f.read()

  final_content = license_content + formatted_output

  build_util.write_if_changed(out_file, final_content)

if __name__ == "__main__":
  main()
