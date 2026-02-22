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
    (R'^\./(\S)', R'\1'),  # handles './abc'
    (R'(\s)\./(\S)', R'\1\2'),  # handles ' ./abc'
    (R'(-.)\./(\S)', R'\1\2'),  # handles '-I./abc'

    # Handle e.g. x/y/lastdir/lastdir.file.o (which is just x/y/lastdir/file.o
    # in scons build format).
    (R'([^/]*)/\1\.([^/]+)\.o', R'\1/\2.o'),

    # special case for the above to handle targets in archs/ under the 'kernel'
    # target.
    (R'kernel\.([^. ]+)\.o', R'\1.o'),
    (R'libkernel_phys\.([^. ]+)\.o', R'\1.o'),
    (R'x86-common\.([^. ]+)\.o', R'\1.o'),
    (R'obj/', 'build-scons/$ARCH-$COMP/'),
    #(R'(apos-\S*) (.*) (-o \S*)', R'\1 \3 \2'),
    (R'-Igen', '-Ibuild-scons/$ARCH-$COMP'),

    # Make lib paths match what scons uses.
    (R'(build-scons/([^/]*)-[^/]*/)archs/[^/]*/(libkernel_phys.a)', R'\1\3'),
    (R'(build-scons/([^/]*)-[^/]*/)main/(libkernel.a)', R'\1\3'),
]

REPLS_NINJA_FIXUP = [
    (R'-MMD *', ''),
    (R'-MF \S* *', ''),
    (R'(-ar .*) rcs', R'\1 rc'),  # scons uses 'rc' rather than 'rcs'
]

NINJA_IGNORE = []
NINJA_FILE_IGNORE = []

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
    (R'dts_to_header\(\["(.*)"\], *\["(.*)"\]\)',
     R'python test/dtb_testdata/gen_dtb_header.py \2 build/license_template.h \1'
    ),

    # Make kernel.bin path match what ninja does (we do it here rather than
    # above so we don't have to generate the arch string from thin air).
    (R'build-scons/[^/]*-[^/]*/kernel.bin', 'kernel.bin'),
]
SCONS_IGNORE = [
    # TODO(aoates): get rid of all of these as we migrate more to gn.
    R'^Install file: .*',
    R'^scons: .*',
    R'^ar rc .*',
    R'.*\.tpl: \S*-pc-apos-ar ',  # Final ar.. line that gets mangled a bit
    R'cc.*passwd_test',
    R'^config_h_builder(.*)',
    #R'^\S*-pc-apos-ar rc .*/os/common/libcommon.a',
    #R'^\S*-pc-apos-ar rc .*/user-tests/libktest.a',
    #R'^\S*-pc-apos-ar rc .*/user/header_tests/libapos_header_tests.a',
    #R'^\S*-pc-apos-ar rc .*/user/libapos_syscall.a',
    #R'^\S*-pc-apos-gcc .*/os/.*',
    #R'^\S*-pc-apos-ld -o \S*kernel.bin',
    R'^g++.*',
    R'^xxd.* os/core/loader/testdata.*',

    # Thinks we do not intend to port to ninja:
    R'^ranlib .*native-common.a',
    R'^\S*-pc-apos-ranlib .*',  # gn doesn't do ranlib
    R'.*kernel.bin.stripped.*',
]
SCONS_FILE_IGNORE = [
    R'(build-scons/[^/]*/)?user-tests/.*',
    R'(build-scons/[^/]*/)?os/.*',
    R'(build-scons/[^/]*/)?user/.*',
]

def parse_line(line: str) -> (str, str):
  """Returns (ftype, fname, cmd, args) for a line."""
  m = re.match(R'dts_to_header\(\["(.*)"\], *\["(.*)"\]\)', line)
  if m:
    return ('c', m.group(1), line, [line])
  m = re.match(R'python .*gen_dtb_header.py \S* \S* (.*)', line)
  if m:
    return ('c', m.group(1), line, [line])
  # perl -p -e 's/((.*) ([.\/_a-zA-Z0-9-]*\.([cs]|tpl))\W)/\3: \1/g' | \
  m = re.match(R'^(\S+)(.*\W([.\/_a-zA-Z0-9-]*\.([cso]|tpl|so|m4|bin))\b.*)', line)
  if not m:
    return (None, None, None, None)
  cmd = m.group(1)
  args = m.group(2).split()

  if cmd == 'python':
    cmd = cmd + ' ' + args[0]
    args = args[1:]

  # Find the input filename.  .tpl/.m4 take priority so we get the input file
  # (the .tpl/.m4 file) rather than the output file.
  fname = None
  ftype = 'other'
  for arg in args:
    if arg.endswith('.tpl'):
      ftype = 'tpl'
      fname = arg
      break
    elif arg.endswith('.m4'):
      ftype = 'm4'
      fname = arg
      break
    elif arg.endswith('.s'):
      ftype = 'asm'
      fname = arg
    elif arg.endswith('.c'):
      ftype = 'c'
      fname = arg

  # If we didn't find a source file, look for the output file to use.
  if not fname:
    m = re.search(R'\s-o\s*(\S+)', line)
    if m:
      fname = m.group(1)
  if not fname:
    fname = '<?>'

  if cmd.endswith('-ar'):
    fname = args[1]
  return (ftype, fname, cmd, args)


arch = None
comp = None
def normalize(line: str, repls: Sequence[tuple[str, str]],
              file_ignores: Sequence[re.Pattern]):
  ftype, fname, cmd, args = parse_line(line)
  if not ftype:
    return line.strip()
  for p in file_ignores:
    if p.match(fname):
      print(f'Ignored: {fname}', file=sys.stderr)
      return None

  args_out = []
  append_next = False
  for a in args:
    if append_next:
      append_next = False
      args_out[-1] = args_out[-1] + ' ' + a
      continue

    if a in {'-o', '-MF', '-I', '-T', '-L', '-z'}:
      append_next = True
    args_out.append(a)

  # Apply the substitutions to each argument _before_ sorting.
  def do_repls(s : str) -> str:
    for pat, rep in repls:
      s = re.sub(pat, rep, s)
    return s

  args_out = [do_repls(arg) for arg in args_out]
  args_out = [a for a in args_out if a]
  args_out.sort()

  args_out = ' '.join(args_out)
  line = f'[{ftype}] {fname}: {cmd} {args_out}'
  # Apply substitutions to the whole thing again at the end (for multi-arg
  # substitutions).
  line = do_repls(line)

  if arch:
    line = line.replace('$ARCH', arch)
  if comp:
    line = line.replace('$COMP', comp)
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
    extra, extra_fixup, ignores, file_ignores = (REPLS_SCONS, REPLS_SCONS_FIXUP,
                                                 SCONS_IGNORE,
                                                 SCONS_FILE_IGNORE)
  elif args.type == 'ninja':
    extra, extra_fixup, ignores, file_ignores = (REPLS_NINJA, REPLS_NINJA_FIXUP,
                                                 NINJA_IGNORE,
                                                 NINJA_FILE_IGNORE)
  else:
    extra, extra_fixup, ignores = [], [], []

  repls.extend(extra)
  if args.fixup:
    repls.extend(extra_fixup)

  # First read everything to determine the arch and compiler.
  lines = []
  global arch, comp
  for line in sys.stdin:
    line = line.strip()
    lines.append(line)
    if not arch:
      for a in ('i586', 'x86_64', 'riscv64'):
        if a in line:
          arch = a
          break
    if arch and not comp:
      for c in ('clang', 'gcc'):  # Must be in this order
        if f'{arch}-pc-apos-{c}' in line:
          comp = c
          break

  # Now process the lines.
  repls_c = [(re.compile(p), r) for p, r in REPLS]
  ignores = [re.compile(p) for p in ignores]
  file_ignores = [re.compile(p) for p in file_ignores]
  for line in lines:
    ignore = False
    if args.ignores:
      for p in ignores:
        if p.match(line):
          ignore=True
          break
    if not ignore:
      out = normalize(line, repls_c, file_ignores)
      if out:
        print(out)

if __name__ == '__main__':
  main(sys.argv)
