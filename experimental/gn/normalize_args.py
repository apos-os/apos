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
# Normalizes and tweaks arguments to compilation commands to make them easier to
# diff.  Has two types of changes that it does:
#  * normalization: changes paths and object names to be the same between scons
#    and ninja so that files can be diffed correctly.
#  * fixups: if --fixup is set, also tweaks the command lines to remove known
#    harmless diffs (such as certain flags that are specified twice).

import argparse
import re
import sys

from typing import Sequence, Optional

REPLS = []

REPLS_NINJA = [
    (R'\.\./\.\.', '.'),
    (R'\./', ''),

    # Handle e.g. x/y/lastdir/lastdir.file.o (which is just x/y/lastdir/file.o
    # in scons build format).
    (R'([^/]*)/\1\.([^.]+)\.o', R'\1/\2.o'),

    # special case for the above to handle targets in archs/ under the 'kernel'
    # target.
    (R'kernel\.([^.]*)\.o', R'\1.o'),
    (R'libkernel_phys\.([^.]*)\.o', R'\1.o'),
    (R'x86-common\.([^.]*)\.o', R'\1.o'),
    (R'obj/', 'build-scons/$ARCH-gcc/'),
    #(R'(apos-\S*) (.*) (-o \S*)', R'\1 \3 \2'),
    (R'-Igen', '-Ibuild-scons/$ARCH-gcc'),
]

REPLS_NINJA_FIXUP = [
    (R'-MMD *', ''),
    (R'-MF \S* *', ''),
]

REPLS_SCONS = []
REPLS_SCONS_FIXUP = [
    # scons version has two -I.
    (R'-I\. *-I\.', '-I.'),

    # scons version has two --gen-debug
    (R'--gen-debug --gen-debug', '--gen-debug'),
]

REPLS_C = None

arch = None
def normalize(line: str):
  global arch
  line = line.strip()
  if not arch:
    for a in ('i586', 'x86_64', 'riscv64'):
      if a in line:
        arch = a
        break

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

  if arch:
    line = line.replace('$ARCH', arch)
  return line

def main(argv: Optional[Sequence[str]] = None):
  parser = argparse.ArgumentParser()
  parser.add_argument(
      '--fixup',
      action='store_true',
      help=
      'Fix up known diffs.  If not set, the raw normalized arguments are used.')
  parser.add_argument(
      '--type',
      choices=['scons', 'ninja'],
      help='The type of log being processed.  Controls per-tool fixups.')
  args = parser.parse_args()

  repls = REPLS
  if args.type == 'scons':
    extra, extra_fixup = REPLS_SCONS, REPLS_SCONS_FIXUP
  elif args.type == 'ninja':
    extra, extra_fixup = REPLS_NINJA, REPLS_NINJA_FIXUP
  else:
    extra, extra_fixup = [], []

  repls.extend(extra)
  if args.fixup:
    repls.extend(extra_fixup)

  global REPLS_C
  REPLS_C = [(re.compile(p), r) for p, r in REPLS]
  for line in sys.stdin:
    print(normalize(line))

if __name__ == '__main__':
  main(sys.argv)
