#!/bin/bash
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

# Performs a clean build for all configurations (arch+compiler combos plus TSAN
# variants), normalizes each build command with --nonormalize, and writes each
# configuration's build lines (sorted) into a separate file at
# experimental/gn/logs/build_log.$config.log.

set -e
set -o pipefail

LOGS_DIR=experimental/gn/logs
NORMALIZE=./experimental/gn/normalize_args.py

ARCHS=(riscv64 i586 x86_64)
COMPS=(gcc clang)

do_capture() {
  local arch=$1
  local comp=$2
  local variant=$3
  local enable_values=$4
  local label=$arch-$comp${variant:+-$variant}
  local outfile=$LOGS_DIR/build_log.$label.log

  local configure_args="--arch $arch --compiler=$comp --mode=gn"
  if [ -n "$enable_values" ]; then
    configure_args="$configure_args --enable=$enable_values"
  fi

  ./configure $configure_args 1>&2
  ninja -C out -v 2>/dev/null \
    | grep -E '^\[[0-9]+/[0-9]+\]' \
    | perl -p -e 's/^\[\d*\/\d*\] *//g' \
    | $NORMALIZE --nonormalize --type=ninja \
    | sort > "$outfile"
  echo "Captured $label to $outfile" >&2
}

mkdir -p "$LOGS_DIR"

# Remove source-tree generated files so they are regenerated during the build.
rm -f syscall/syscall_dispatch.tpl.c
rm -f syscall/syscall_dmz.tpl.c
rm -f test/dtb_testdata/interrupt_test.dts.h
rm -f test/dtb_testdata/large_golden.dts.h
rm -f test/dtb_testdata/long_string.dts.h
rm -f test/dtb_testdata/parse_test.dts.h
rm -f test/dtb_testdata/small_golden.dts.h
rm -f user/include/apos/syscall_decls.h
rm -f user/include/apos/syscalls.h
rm -f user/newlib_syscall_stubs.tpl.c
rm -f user-tests/syscall_link_test.c
rm -f os/core/loader/syscalls.h
rm -f os/core/loader/syscalls.c
rm -f os/core/loader/testdata/gnu_hash_lib.so
rm -f os/core/loader/testdata/gnu_hash_lib.so.cdata

# Remove the entire build directory for a clean build.
rm -rf out-gn

for arch in "${ARCHS[@]}"; do
  for comp in "${COMPS[@]}"; do
    do_capture "$arch" "$comp"
  done
done

do_capture riscv64 clang tsan TSAN_FULL
