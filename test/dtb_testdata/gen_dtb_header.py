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

import subprocess
import sys
import os

# Hack up python path so we can import build_util.
from pathlib import Path
root_dir = Path(__file__).resolve().parent.parent.parent
sys.path.append(str(root_dir))

from util import build_util

def main():
  if len(sys.argv) != 4:
    print(f"Usage: {sys.argv[0]} <dts_file> <license_template> <out_file>",
          file=sys.stderr)
    sys.exit(1)

  dts_file = sys.argv[1]
  license_file = sys.argv[2]
  out_file = sys.argv[3]

  # Run dtc, pipe to xxd -i
  dtc_cmd = ['dtc', '-I', 'dts', '-O', 'dtb', dts_file]
  xxd_cmd = ['xxd', '-i']

  dtc_proc = subprocess.Popen(dtc_cmd,
                              stdout=subprocess.PIPE,
                              stderr=sys.stderr)
  xxd_proc = subprocess.run(xxd_cmd, stdin=dtc_proc.stdout, capture_output=True)
  dtc_proc.wait()

  if dtc_proc.returncode != 0:
    sys.exit(dtc_proc.returncode)

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
