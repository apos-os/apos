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

# Opens each SConscript/SConstruct file alongside its corresponding GN file(s)
# in vim for a side-by-side review.  Press any key to open the next pair,
# 's' to skip it, or 'q' to quit.

REPO=$(cd "$(dirname "$0")/../.." && pwd)
echo "Repo root: $REPO"

review() {
  local label=$1
  shift
  printf '\n========================================\n'
  printf '  %s\n' "$label"
  printf '========================================\n'
  printf "Press any key to open, 's' to skip, 'q' to quit... "
  read -r -n1 key
  echo
  case "$key" in
    q) exit 0 ;;
    s) return ;;
  esac
  local files=()
  for f in "$@"; do
    files+=("$REPO/$f")
  done
  vim -O "${files[@]}"
}

# SConstruct maps to multiple GN files covering features, configs, and templates.
review "SConstruct → build/{features.gni,config/BUILD.gn,templates.gni}" \
  SConstruct \
  build/features.gni \
  build/config/BUILD.gn \
  build/templates.gni

review "SConscript (root) → BUILD.gn" \
  SConscript \
  BUILD.gn

# archs/ — the top-level SConscript just wires subdirs; consolidate load/
# SConscripts with their parent arch BUILD.gn since they're merged there.
review "archs/SConscript → (top-level archs BUILD.gns)" \
  archs/SConscript \
  archs/i586/BUILD.gn \
  archs/riscv64/BUILD.gn \
  archs/x86_64/BUILD.gn

review "archs/i586 + i586/internal/load → archs/i586/BUILD.gn" \
  archs/i586/SConscript \
  archs/i586/internal/load/SConscript \
  archs/i586/BUILD.gn

review "archs/riscv64 → archs/riscv64/BUILD.gn" \
  archs/riscv64/SConscript \
  archs/riscv64/BUILD.gn

review "archs/riscv64/internal/load → archs/riscv64/internal/BUILD.gn" \
  archs/riscv64/internal/load/SConscript \
  archs/riscv64/internal/BUILD.gn

review "archs/x86-common → archs/x86-common/BUILD.gn" \
  archs/x86-common/SConscript \
  archs/x86-common/BUILD.gn

review "archs/x86_64 + x86_64/internal/load → archs/x86_64/BUILD.gn" \
  archs/x86_64/SConscript \
  archs/x86_64/internal/load/SConscript \
  archs/x86_64/BUILD.gn

review "common → common/BUILD.gn" \
  common/SConscript \
  common/BUILD.gn

review "dev → dev/BUILD.gn" \
  dev/SConscript \
  dev/BUILD.gn

review "dev/ata → dev/ata/BUILD.gn" \
  dev/ata/SConscript \
  dev/ata/BUILD.gn

review "dev/devicetree → dev/devicetree/BUILD.gn" \
  dev/devicetree/SConscript \
  dev/devicetree/BUILD.gn

review "dev/keyboard → dev/keyboard/BUILD.gn" \
  dev/keyboard/SConscript \
  dev/keyboard/BUILD.gn

review "dev/net → dev/net/BUILD.gn" \
  dev/net/SConscript \
  dev/net/BUILD.gn

review "dev/nvme → dev/nvme/BUILD.gn" \
  dev/nvme/SConscript \
  dev/nvme/BUILD.gn

review "dev/pci → dev/pci/BUILD.gn" \
  dev/pci/SConscript \
  dev/pci/BUILD.gn

review "dev/ramdisk → dev/ramdisk/BUILD.gn" \
  dev/ramdisk/SConscript \
  dev/ramdisk/BUILD.gn

review "dev/rtc → dev/rtc/BUILD.gn" \
  dev/rtc/SConscript \
  dev/rtc/BUILD.gn

review "dev/serial → dev/serial/BUILD.gn" \
  dev/serial/SConscript \
  dev/serial/BUILD.gn

review "dev/usb → dev/usb/BUILD.gn" \
  dev/usb/SConscript \
  dev/usb/BUILD.gn

review "dev/usb/drivers → dev/usb/drivers/BUILD.gn" \
  dev/usb/drivers/SConscript \
  dev/usb/drivers/BUILD.gn

review "dev/usb/drivers/hub → dev/usb/drivers/hub/BUILD.gn" \
  dev/usb/drivers/hub/SConscript \
  dev/usb/drivers/hub/BUILD.gn

review "dev/usb/uhci → dev/usb/uhci/BUILD.gn" \
  dev/usb/uhci/SConscript \
  dev/usb/uhci/BUILD.gn

review "dev/video → dev/video/BUILD.gn" \
  dev/video/SConscript \
  dev/video/BUILD.gn

review "main → main/BUILD.gn" \
  main/SConscript \
  main/BUILD.gn

review "memory → memory/BUILD.gn" \
  memory/SConscript \
  memory/BUILD.gn

review "net → net/BUILD.gn" \
  net/SConscript \
  net/BUILD.gn

review "net/eth → net/eth/BUILD.gn" \
  net/eth/SConscript \
  net/eth/BUILD.gn

review "net/eth/arp → net/eth/arp/BUILD.gn" \
  net/eth/arp/SConscript \
  net/eth/arp/BUILD.gn

review "net/ip → net/ip/BUILD.gn" \
  net/ip/SConscript \
  net/ip/BUILD.gn

review "net/ip/icmpv6 → net/ip/icmpv6/BUILD.gn" \
  net/ip/icmpv6/SConscript \
  net/ip/icmpv6/BUILD.gn

review "net/socket → net/socket/BUILD.gn" \
  net/socket/SConscript \
  net/socket/BUILD.gn

review "net/socket/tcp → net/socket/tcp/BUILD.gn" \
  net/socket/tcp/SConscript \
  net/socket/tcp/BUILD.gn

review "os → os/BUILD.gn" \
  os/SConscript \
  os/BUILD.gn

review "os/common → os/common/BUILD.gn" \
  os/common/SConscript \
  os/common/BUILD.gn

review "os/core → os/core/BUILD.gn" \
  os/core/SConscript \
  os/core/BUILD.gn

review "os/core/loader → os/core/loader/BUILD.gn" \
  os/core/loader/SConscript \
  os/core/loader/BUILD.gn

review "proc → proc/BUILD.gn" \
  proc/SConscript \
  proc/BUILD.gn

review "proc/load → proc/load/BUILD.gn" \
  proc/load/SConscript \
  proc/load/BUILD.gn

review "proc/signal → proc/signal/BUILD.gn" \
  proc/signal/SConscript \
  proc/signal/BUILD.gn

review "sanitizers → sanitizers/BUILD.gn" \
  sanitizers/SConscript \
  sanitizers/BUILD.gn

review "sanitizers/tsan → sanitizers/tsan/BUILD.gn" \
  sanitizers/tsan/SConscript \
  sanitizers/tsan/BUILD.gn

review "syscall → syscall/BUILD.gn" \
  syscall/SConscript \
  syscall/BUILD.gn

review "test → test/BUILD.gn" \
  test/SConscript \
  test/BUILD.gn

review "test/dtb_testdata → test/dtb_testdata/BUILD.gn" \
  test/dtb_testdata/SConscript \
  test/dtb_testdata/BUILD.gn

review "test/ext2 → test/ext2/BUILD.gn" \
  test/ext2/SConscript \
  test/ext2/BUILD.gn

review "test/i586 → test/i586/BUILD.gn" \
  test/i586/SConscript \
  test/i586/BUILD.gn

review "test/riscv64 → test/riscv64/BUILD.gn" \
  test/riscv64/SConscript \
  test/riscv64/BUILD.gn

review "test/tsan → test/tsan/BUILD.gn" \
  test/tsan/SConscript \
  test/tsan/BUILD.gn

review "user → user/BUILD.gn" \
  user/SConscript \
  user/BUILD.gn

review "user/header_tests → user/header_tests/BUILD.gn" \
  user/header_tests/SConscript \
  user/header_tests/BUILD.gn

review "user/include → user/include/BUILD.gn" \
  user/include/SConscript \
  user/include/BUILD.gn

review "user-tests → user-tests/BUILD.gn" \
  user-tests/SConscript \
  user-tests/BUILD.gn

review "util → util/BUILD.gn" \
  util/SConscript \
  util/BUILD.gn

review "vfs → vfs/BUILD.gn" \
  vfs/SConscript \
  vfs/BUILD.gn

review "vfs/ext2 → vfs/ext2/BUILD.gn" \
  vfs/ext2/SConscript \
  vfs/ext2/BUILD.gn

printf '\nDone! All %d pairs reviewed.\n' 55
