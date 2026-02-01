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

import re
import sys

REPLS = [
    (R'-MMD *', ''),
    (R'-MF \S* *', ''),
    (R'\.\./\.\.', '.'),
    (R'\./', ''),
    # Handle e.g. x/y/lastdir/lastdir.file.o (which is just x/y/lastdir/file.o
    # in scons build format).
    (R'([^/]*)/\1\.([^.]*)\.o', R'\1/\2.o'),

    # special case for the above to handle targets in archs/ under the 'kernel'
    # target.
    (R'kernel\.([^.]*)\.o', R'\1.o'),
    (R'libkernel_phys\.([^.]*)\.o', R'\1.o'),
    (R'x86-common\.([^.]*)\.o', R'\1.o'),

    (R'obj/', 'build-scons/i586-gcc/'),
    #(R'(apos-\S*) (.*) (-o \S*)', R'\1 \3 \2'),
    (R'-Igen', '-Ibuild-scons/i586-gcc'),

    # scons version has two -I.
    (R'-I\. *-I\.', '-I.'),

    # scons version has two
    (R'--gen-debug --gen-debug', '--gen-debug'),
]

REPLS_C = [(re.compile(p), r) for p, r in REPLS]

def normalize(line: str):
  line = line.strip()

  m = re.match(R'^([^:]*): (\S*)\s+(.*)$', line)
  if not m:
    return line.strip()

  fname = m.group(1)
  cmd = m.group(2)
  args = m.group(3).split()
  args_out = []
  append_next = False
  for a in args:
    if append_next:
      append_next = False
      args_out[-1] = args_out[-1] + ' ' + a
      continue

    if a in {'-o', '-MF', '-I'}:
      append_next = True
    args_out.append(a)
  args_out.sort()

  args_out = ' '.join(args_out)
  line = f'{fname}: {cmd} {args_out}'
  for pat, rep in REPLS_C:
    line = re.sub(pat, rep, line)

  return line

for line in sys.stdin:
  print(normalize(line))
