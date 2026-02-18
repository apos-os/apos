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

# Does a build for all three architectures and dumps out the build commands,
# then normalizes them and compares between scons and ninja.

do_ninja_build() {
  ARCH=$1
  comp=$2
  rm -rf out/$ARCH-$comp && gn gen out/$ARCH-$comp --args="target_cpu=\"$ARCH\" compiler=\"$comp\"" && ninja -C out/$ARCH-$comp -v | tee ninja_build_log.$ARCH.$comp.log
}

do_compare() {
  arch=$1
  comp=$2
  cat ninja_build_log.$arch.$comp.log | ./experimental/gn/fix_ninja_log.sh \
    --fixup \
    --type=ninja \
    > /tmp/ninja_log
  if [ "$comp" = "gcc" ]; then
    comp2=CLANG=0
  else
    comp2=CLANG=1
  fi
  cat build_log.$arch.$comp2.log | ./experimental/gn/fix_scons_log.sh \
    --fixup \
    --type=scons \
    > /tmp/scons_log

  vimdiff /tmp/scons_log /tmp/ninja_log
}

ARCHS=(i586 x86_64 riscv64)
COMPS=(gcc clang)
for arch in ${ARCHS[@]}; do
  for comp in ${COMPS[@]}; do
    do_ninja_build $arch $comp
    do_compare $arch $comp
  done
done
