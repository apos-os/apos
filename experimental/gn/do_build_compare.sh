#!/bin/bash -x
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

set -e
set -o pipefail

DIFF=${DIFF:-vimdiff}

# Does a build for all three architectures and dumps out the build commands,
# then normalizes them and compares between scons and ninja.

do_ninja_build() {
  local arch=$1
  local comp=$2

  # Configure and do a quick check to see if anything needs to be rebuilt.
  # If nothing has changed, the existing log is still valid.
  ./configure --arch $arch --compiler=$comp --mode=gn
  if ninja -n -C out 2>&1 | grep -q "ninja: no work to do"; then
    echo "Nothing changed for $arch/$comp, keeping existing log." >&2
    return 0
  fi

  # Something was (or would be) rebuilt; do a full clean rebuild for a
  # canonical log.
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
  if [ "${arch}" != "x86_64" ]; then
    rm -f user-tests/syscall_link_test.c
  fi
  if [ "${arch}" = "riscv64" ]; then
    rm -f os/core/loader/syscalls.h
    rm -f os/core/loader/syscalls.c
    rm -f os/core/loader/testdata/gnu_hash_lib.so
    rm -f os/core/loader/testdata/gnu_hash_lib.so.cdata
  fi
  rm -rf out/$arch-$comp out/native \
    && ./configure --arch $arch --compiler=$comp --mode=gn \
    && ninja -C out -v | tee ninja_build_log.$arch.$comp.log
}

do_compare() {
  arch=$1
  comp=$2
  cat ninja_build_log.$arch.$comp.log | ./experimental/gn/fix_ninja_log.sh \
    --fixup \
    --type=ninja \
    > /tmp/ninja_log
  cat build_log.$arch.$comp.log | ./experimental/gn/fix_scons_log.sh \
    --fixup \
    --type=scons \
    > /tmp/scons_log

  $DIFF /tmp/scons_log /tmp/ninja_log
}

ARCHS=(riscv64 i586 x86_64)
COMPS=(gcc clang)
for arch in ${ARCHS[@]}; do
  for comp in ${COMPS[@]}; do
    do_ninja_build $arch $comp
    do_compare $arch $comp
  done
done
