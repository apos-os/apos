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

REPLS = [
    # Normalize -I <build-scons/> (with space) to -Ibuild-scons/ (no space),
    # since scons uses space-separated and gn uses concatenated form.
    (R'-I (build-scons/)', r'-Ibuild-scons/'),
]

REPLS_NINJA = [
    (R'\.\.', '.'),
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
    (R'kernel_phys_src\.([^. ]+)\.o', R'\1.o'),
    (R'x86-common\.([^. ]+)\.o', R'\1.o'),
    (R'all_tests\.([^. ]+)\.o', R'\1.o'),
    (R'libcommon-lib\.([^. ]+)\.o', R'\1.o'),
    (R'libcommon\.([^. ]+)\.o', R'\1.o'),
    (R'core/([^/ ]*).\1\.o', R'core/\1.o'),
    (R'passwd_test\.([^. ]+)\.o', R'\1.o'),
    (R'libapos_header_tests\.([^. ]+)\.o', R'\1.o'),
    (R'libapos_user_dummy\.([^. ]+)\.[oa]', R'\1.o'),
    # newlib_syscall_stubs.tpl.o has dots so the above doesn't match it;
    # handle it explicitly.
    (R'libapos_user_dummy\.newlib_syscall_stubs', R'newlib_syscall_stubs'),
    (R'libapos_syscall\.([^. ]+)\.o', R'\1.o'),
    (R'syscall_link_test\.([^. ]+)\.o', R'\1.o'),

    (R'\S+-\S+/obj/', 'build-scons/$ARCH-$COMP/'),
    #(R'(apos-\S*) (.*) (-o \S*)', R'\1 \3 \2'),
    (R'-I\S+-\S+/gen', '-Ibuild-scons/$ARCH-$COMP'),

    # Make lib paths match what scons uses.
    (R'(build-scons/([^/]*)-[^/]*/)archs/[^/]*/(libkernel_phys.a)', R'\1\3'),
    (R'(build-scons/([^/]*)-[^/]*/)main/(libkernel\.a)', R'\1\3'),

    # Normalize user-test/os binary output paths in -o args (scoped to avoid
    # incorrectly stripping object file paths like build-scons/i586-gcc/...).
    (R'(-o )\S+-\S+/(user-tests/(?:all_tests|syscall_link_test)|os/core/\S+)\b', R'\1\2'),

    # Normalize memlayout.m4 output paths: gen/archs/... -> archs/...
    (R'\S+-\S+/gen/archs/riscv64/internal/memlayout\.m4\.(\S+)',
     R'archs/riscv64/internal/memlayout.m4.\1'),

    # Normalize native/... paths.
    (R'native/obj/', 'build-scons/$ARCH-$COMP/'),

    # Native toolchain: gn names the library libcommon-lib.a, scons uses libcommon.a.
    (R'libcommon-lib\.a\b', 'libcommon.a'),
]

REPLS_NINJA_FIXUP = [
    (R'-MMD *', ''),
    (R'-MF \S* *', ''),
    (R'(-ar .*) rcs', R'\1 rc'),  # scons uses 'rc' rather than 'rcs'
    (R'(: ar\b.*) rcs\b', R'\1 rc'),  # same for native ar

    # gn adds --depsfile for tpl_gen.py dep tracking; scons uses its own scanner.
    # --depsfile is grouped with its value (see append_next), so this matches
    # the whole "--depsfile <path>" unit as a single arg.
    (R'^--depsfile \S+$', ''),
    (R'^--import_root \./$', '--import_root .'),

    # gn adds -I. and -Iarchs/... to asm file compilations; scons doesn't.
    # After sorting, these appear as: -I. [-Iarchs/foo ...] -Ibuild-scons/...
    (R'(\[asm\].*?) -I\.(?: -Iarchs/\S+)*(.*)', r'\1\2'),

    # gn adds both -Wframe-larger-than=1500 and -Wframe-larger-than=5000 for
    # test files that override the limit; scons only adds the override value.
    (R'(test/\S*\.c:.*) -Wframe-larger-than=1500 (-Wframe-larger-than=5000)',
     r'\1 \2'),

    # test/riscv64/user_test.c: scons sets a -Wframe-larger-than=5000 override;
    # gn only passes the default 1500.  Normalize ninja to 5000 to match.
    (R'(\[c\] test/riscv64/user_test\.c:.+) -Wframe-larger-than=1500(?= |$)',
     R'\1 -Wframe-larger-than=5000'),

    # gn adds -Wthread-safety* to user/user-tests/os-common/os-core clang files;
    # scons doesn't.  Kernel files have these in both, so don't strip there.
    # Apply longest-suffix-first to avoid partial matches.
    (R'(\[c\] (?:os/(?:common|core)|user(?:-tests)?)/\S+:.*) -Wthread-safety-pointer(?!\S)',
     r'\1'),
    (R'(\[c\] (?:os/(?:common|core)|user(?:-tests)?)/\S+:.*) -Wthread-safety-beta(?!\S)',
     r'\1'),
    (R'(\[c\] (?:os/(?:common|core)|user(?:-tests)?)/\S+:.*) -Wthread-safety(?!-)',
     r'\1'),

    # user/os binary links: scoped to all_tests/syscall_link_test/os/core targets
    # to avoid false matches.
    # scons uses -z noexecstack, gn uses -Wl,-static; strip gn flag.
    (R'(\[other\] (?:user-tests/(?:all_tests|syscall_link_test)|os/core/\S+):.+) -Wl,-static(?= |$)',
     R'\1'),
    # riscv64: gn passes -Wl,--no-relax (scons only passes to ld kernel link).
    (R'(\[other\] (?:user-tests/(?:all_tests|syscall_link_test)|os/core/\S+):.+) -Wl,--no-relax(?= |$)',
     R'\1'),
    # gn links libcommon.a and ktest.o directly; scons uses -L/-l and libktest.a.
    # (libcommon-lib.a was renamed to libcommon.a by REPLS_NINJA)
    (R'(\[other\] (?:user-tests/(?:all_tests|syscall_link_test)|os/core/\S+):.+) build-scons/[^/]*/os/common/libcommon\.a(?= |$)',
     R'\1'),
    (R'(\[other\] user-tests/(?:all_tests|syscall_link_test):.+) build-scons/[^/]*/user-tests/ktest\.o(?= |$)',
     R'\1'),

    # kernel.bin linker: scons uses ld directly, gn uses gcc as linker driver.
    # Use a repl for each literal line so that if these change later, a diff
    # will show up.
    (R'\[other\] kernel\.bin: \S*-pc-apos-gcc -L \./ -L \S+-\S+/gen -T archs/\S*/build/linker\.ld (-Wl,--no-relax )?-Wl,--orphan-handling=error -nostdlib -o \S+-\S+/kernel\.bin -z noexecstack build-scons/\S*-\S*/libkernel\.a build-scons/\S*-\S*/libkernel_phys\.a', '[other] kernel.bin: <known different command>'),

    # Native binary fname: the native/obj/ → build-scons/$ARCH-$COMP/ rule fires
    # on the fname (applied to the full line in step 4), turning
    # 'native/obj/os/common/passwd_test' into 'build-scons/arch/os/common/passwd_test'.
    # scons fname is 'os/common/passwd_test' (arch-comp prefix stripped by fname
    # normalization rule above).  Strip the build-scons/arch-comp/ prefix here.
    # Use [^.:\s]+ to only match extension-less binary fnames, not .a archives.
    (R'(\[\w+\]) build-scons/[^/]*-[^/]*/os/common/([^.:\s]+:)', R'\1 os/common/\2'),
]

NINJA_IGNORE = [
    R'.*gn.*--regeneration gen.*',
]
NINJA_FILE_IGNORE = [
]

REPLS_SCONS = [
    # Normalize memlayout.m4 output paths: build-scons/.../archs/... -> archs/...
    (R'build-scons/[^/]*/archs/riscv64/internal/memlayout\.m4\.(\S+)',
     R'archs/riscv64/internal/memlayout.m4.\1'),

    # Remove 'native-' prefix from paths.
    ('/native-', '/'),
]
REPLS_SCONS_FIXUP = [
    # Native toolchain: scons uses 'cc' (system compiler alias), gn uses 'gcc' explicitly.
    (R'(: )cc\b', R'\1gcc'),

    # Native toolchain: scons builds libcommon as 'native-common.a' (normalized to
    # 'common.a' by REPLS_SCONS '/native-' → '/'); gn names it 'libcommon-lib.a'
    # (normalized to 'libcommon.a' by REPLS_NINJA).  Normalize scons to match.
    (R'(os/common/)common\.a\b', R'\1libcommon.a'),

    # scons version has two -I.
    (R'-I\. *-I\.', '-I.'),

    # scons puts .c.tpl. in syscall_link_test object output filename; gn doesn't.
    (R'syscall_link_test\.c\.tpl\.o\b', r'syscall_link_test.o'),

    # scons outputs newlib_syscall_stubs.tpl.o to the source tree (no build-scons
    # prefix); gn puts it in the build dir with the libapos_user_dummy prefix
    # (which is already normalized away by REPLS_NINJA).
    (R'-o user/newlib_syscall_stubs\.tpl\.o',
     r'-o build-scons/$ARCH-$COMP/user/newlib_syscall_stubs.tpl.o'),

    # scons version has two --gen-debug
    (R'--gen-debug --gen-debug', '--gen-debug'),

    # scons version puts '.PHYS.' in the name
    (R'\.PHYS\.o', '.o'),

    # scons doubles this flag too
    (R'-march=rv64gc -march=rv64gc', '-march=rv64gc'),

    # scons passes both flags
    (R'(test/\S*\.c:.*) -Wframe-larger-than=1500 (-Wframe-larger-than=5000)',
     R'\1 \2'),

    # test/riscv64/user_test.c: scons (clang) adds -Wno-self-assign; gn doesn't.
    (R'(\[c\] test/riscv64/user_test\.c:.+) -Wno-self-assign(?= |$)', R'\1'),
    (R'dts_to_header\(\["(.*)"\], *\["(.*)"\]\)',
     R'python test/dtb_testdata/gen_dtb_header.py \2 build/license_template.h \1'
    ),

    # Make kernel.bin path match what ninja does (we do it here rather than
    # above so we don't have to generate the arch string from thin air).
    (R'build-scons/[^/]*-[^/]*/kernel\.bin', 'kernel.bin'),
    (R'build-scons/[^/]*-[^/]*/user-tests/(all_tests[^.])', R'user-tests/\1'),
    (R'build-scons/[^/]*-[^/]*/user-tests/(syscall_link_test[^.])', R'user-tests/\1'),
    # Normalize the -o output path for os/core binaries and compilation outputs.
    # Scoped to -o so linker inputs (without -o) are unaffected.
    (R'(-o )build-scons/[^/]*-[^/]*/(os/core/\S+)', R'\1\2'),

    # Normalize the -o output path for all_tests.o and syscall_link_test.o
    # compilation outputs.  The existing path normalization rule uses [^.] to
    # exclude target-prefixed linker inputs like all_tests.basic_signal_test.o,
    # but that also excludes the compilation output all_tests.o.  Scope with -o
    # so we only match compiler -o args, not the linker inputs.
    (R'(-o )build-scons/[^/]*-[^/]*/user-tests/((?:all_tests|syscall_link_test)\.o)\b',
     R'\1user-tests/\2'),

    # Normalize fnames that have a spurious arch-comp/ prefix.  scons paths like
    # build-scons/arch-comp/user-tests/all_tests cause parse_line to extract
    # arch-comp/user-tests/all_tests as the fname; strip the arch-comp/ prefix
    # so the scoped rules below can fire.
    (R'(\[\w+\]) [^/\s]+-[^/\s]+/((?:user-tests|os|user|kernel\.bin)\S*?:)',
     R'\1 \2'),

    # user/os binary links: scoped to all_tests/syscall_link_test/os/core targets
    # to avoid false matches.
    # Must come after the path normalization above so fname is in normalized form.
    # scons uses -z noexecstack, gn uses -Wl,-static; strip scons flag.
    (R'(\[other\] (?:user-tests/(?:all_tests|syscall_link_test)|os/core/\S+):.+) -z noexecstack(?= |$)',
     R'\1'),
    # scons links libcommon via -L/-l, gn links libcommon.a directly.
    (R'(\[other\] (?:user-tests/(?:all_tests|syscall_link_test)|os/core/\S+):.+) -Lbuild-scons/[^/]*-[^/]*/os/common(?= |$)',
     R'\1'),
    (R'(\[other\] (?:user-tests/(?:all_tests|syscall_link_test)|os/core/\S+):.+) -Los/common(?= |$)',
     R'\1'),
    (R'(\[other\] (?:user-tests/(?:all_tests|syscall_link_test)|os/core/\S+):.+) -lcommon(?= |$)',
     R'\1'),
    # scons uses libktest.a, gn links ktest.o directly; strip from scons.
    (R'(\[other\] user-tests/(?:all_tests|syscall_link_test):.+) build-scons/[^/]*/user-tests/libktest\.a(?= |$)',
     R'\1'),

    # kernel.bin linker: scons uses ld directly, gn uses gcc as linker driver.
    # Use a repl for each literal line so that if these change later, a diff
    # will show up.
    (R'\[other\] kernel\.bin: \S*-pc-apos-ld (--no-relax )?--orphan-handling=error -L build-scons/\S*-\S* -T archs/\S*/build/linker\.ld -o kernel\.bin -z noexecstack build-scons/\S*-\S*/libkernel\.a build-scons/\S*-\S*/libkernel_phys\.a', '[other] kernel.bin: <known different command>'),

    # libapos_user_dummy.a: make the command line look like ninja's.
    (R'(\[other\] (build-scons/\S*-\S*)/user/libapos_user_dummy\.a: \S*-pc-apos-ar build-scons/\S*-\S*/user/archs/\S*/syscall\.o build-scons/\S*-\S*/user/libapos_user_dummy\.a) (build-scons/\S*-\S*/user/select\.o) rc (user/newlib_syscall_stubs\.tpl\.o)', R'\1 \2/\4 \3 rc'),
]
SCONS_IGNORE = [
    # TODO(aoates): get rid of all of these as we migrate more to gn.
    R'^Install file: .*',
    R'^scons: .*',
    R'.*\.tpl: \S*-pc-apos-ar ',  # Final ar.. line that gets mangled a bit
    #R'^\S*-pc-apos-ar rc .*/os/common/libcommon.a',
    #R'^\S*-pc-apos-ar rc .*/user-tests/libktest.a',
    #R'^\S*-pc-apos-ar rc .*/user/libapos_syscall.a',
    #R'^\S*-pc-apos-gcc .*/os/.*',
    #R'^\S*-pc-apos-ld -o \S*kernel.bin',
    R'^g++.*',
    R'^xxd.* os/core/loader/testdata.*',

    # Thinks we do not intend to port to ninja:
    R'^\S*-pc-apos-ranlib .*',  # gn doesn't do ranlib
    R'^ranlib .*',  # gn doesn't do ranlib (native ranlib)
    R'.*kernel.bin.stripped.*',
]
SCONS_FILE_IGNORE = [
    #R'(build-scons/[^/]*/)?user-tests/.*',
    R'(?:[^/]+-[^/]+/)?(?:build-scons/[^/]*/)?os/core/loader.*',
    #R'(build-scons/[^/]*/)?user/.*',

    # libktest.a: scons builds this separately; gn links ktest.o directly.
    R'^(?:build-scons/[^/]*/)?user-tests/libktest\.a$',
]

def parse_line(line: str) -> (str, str):
  """Returns (ftype, fname, cmd, args) for a line."""
  m = re.match(R'dts_to_header\(\["(.*)"\], *\["(.*)"\]\)', line)
  if m:
    return ('c', m.group(1), line, [line])
  m = re.match(R'python .*gen_dtb_header.py \S* \S* (.*)', line)
  if m:
    return ('c', m.group(1), line, [line])
  # ninja: python .../config_gen.py <input.h.in> <gen/output.h> KEY=val ...
  # Strip the gen/ prefix (build-time generated dir) to get the bare output path.
  # The input path (e.g. ../../common/debug.h.in) is normalized by REPLS_NINJA.
  m = re.match(R'python \S*config_gen\.py (\S+) (?:\S+-\S+/gen/)?(\S+)', line)
  if m:
    return ('h', m.group(2), 'config_gen', [m.group(1)])
  # scons: config_h_builder(["build-scons/ARCH-COMP/output.h"], ["input.h.in"])
  # Strip the build-scons/ARCH-COMP/ prefix to get the bare output path.
  m = re.match(R'config_h_builder\(\["(?:build-scons/[^/]*/)?([^"]+)"\], *\["([^"]+)"\]\)', line)
  if m:
    return ('h', m.group(1), 'config_gen', [m.group(2)])
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
    m = re.search(R'\s-o\s*([_a-zA-Z0-9]+-[_a-zA-Z0-9]+/)?(\S+)', line)
    if m:
      fname = m.group(2)
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

    if a in {'-o', '-MF', '-I', '-T', '-L', '-z', '--depsfile', '--outfile',
             '--import_root'}:
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
