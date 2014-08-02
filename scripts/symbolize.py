#!/usr/bin/python
# Copyright 2014 Andrew Oates.  All Rights Reserved.
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

# Given a log file, look for stack traces and symbolize them.

import re
import sys
import subprocess

def symbolize(frame_num, addr):
  p = subprocess.Popen(["addr2line", "-f", "-s", "-e",
                        "build-scons/kernel.bin", addr],
                       stdout=subprocess.PIPE)
  output = p.communicate()[0].split('\n')
  function = output[0]
  file_line = output[1]
  return ' #%s %s in %s() [%s]\n' % (frame_num, addr, function, file_line)

try:
  while True:
    line = sys.stdin.readline()
    m = re.match(" #(\d*) (0x[a-zA-Z0-9]*)\n", line)
    if m:
      line = symbolize(m.group(1), m.group(2))
    print line,
except KeyboardInterrupt:
  sys.stdout.flush()
  pass
