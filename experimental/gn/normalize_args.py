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

NINJA_IGNORE = []

REPLS_SCONS = []
REPLS_SCONS_FIXUP = [
    # scons version has two -I.
    (R'-I\. *-I\.', '-I.'),

    # scons version has two --gen-debug
    (R'--gen-debug --gen-debug', '--gen-debug'),

    # scons version puts '.PHYS.' in the name
    (R'\.PHYS\.o', '.o'),

    # scons doubles this flag too
    (R'-march=rv64gc -march=rv64gc', '-march=rv64gc'),

    # scons passes both flags
    (R'(test/\S*\.c:.*) -Wframe-larger-than=1500 (-Wframe-larger-than=5000)',
     R'\1 \2'),
]
SCONS_IGNORE = [
    # TODO(aoates): get rid of all of these as we migrate more to gn.
    R'^Install file: .*',
    R'^ar rc .*',
    R'.*\.tpl: \S*-pc-apos-ar ',  # Final ar.. line that gets mangled a bit
    R'[^:]*/user-tests/.*:',
    R'[^:]*/os/.*:',
    R'^os/[^:]*:',
    R'^user-tests/.*\.[cs]:',
    R'^user/.*\.[cs]:',
    R'cc.*passwd_test',
    R'^config_h_builder(.*)',
    R'^dts_to_header(.*)',
    R'^\S*-pc-apos-ar rc .*libkernel_phys.a',
    R'^\S*-pc-apos-ar rc .*/os/common/libcommon.a',
    R'^\S*-pc-apos-ar rc .*/user-tests/libktest.a',
    R'^\S*-pc-apos-ar rc .*/user/header_tests/libapos_header_tests.a',
    R'^\S*-pc-apos-ar rc .*/user/libapos_syscall.a',
    R'^\S*-pc-apos-gcc .*/os/.*',
    R'^\S*-pc-apos-ld -o \S*kernel.bin',
    R'^\S*-pc-apos-ranlib .*',
    R'^ranlib .*native-common.a',
]

arch = None
def normalize(line: str, repls: Sequence[tuple[str, str]]):
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
  for pat, rep in repls:
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
  parser.add_argument('--ignores',
                      action='store_false',
                      help='Control if ignores are applied')
  args = parser.parse_args()

  repls = REPLS
  if args.type == 'scons':
    extra, extra_fixup, ignores = REPLS_SCONS, REPLS_SCONS_FIXUP, SCONS_IGNORE
  elif args.type == 'ninja':
    extra, extra_fixup, ignores = REPLS_NINJA, REPLS_NINJA_FIXUP, NINJA_IGNORE
  else:
    extra, extra_fixup, ignores = [], [], []

  repls.extend(extra)
  if args.fixup:
    repls.extend(extra_fixup)

  repls_c = [(re.compile(p), r) for p, r in REPLS]
  ignores = [re.compile(p) for p in ignores]
  for line in sys.stdin:
    ignore = False
    if args.ignores:
      for p in ignores:
        if p.match(line):
          ignore=True
          break
    if not ignore:
      print(normalize(line, repls_c))

if __name__ == '__main__':
  main(sys.argv)
