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

import argparse
import os
import shutil
import sys

HEADERS = [
    'apos/_posix_signal_constants.h',
    'apos/_posix_termios_constants.h',
    'apos/auxvec.h',
    'apos/dev.h',
    'apos/errors.h',
    'apos/futex.h',
    'apos/ktest.h',
    'apos/mmap.h',
    'apos/net/socket/inet.h',
    'apos/net/socket/socket.h',
    'apos/net/socket/tcp.h',
    'apos/net/socket/unix.h',
    'apos/posix_signal.h',
    'apos/posix_types.h',
    'apos/resource.h',
    'apos/sleep.h',
    'apos/syscall.h',
    'apos/syscalls.h',
    'apos/syscall_decls.h',
    'apos/termios.h',
    'apos/test.h',
    'apos/thread.h',
    'apos/time_types.h',
    'apos/vfs/dirent.h',
    'apos/vfs/fcntl.h',
    'apos/vfs/poll.h',
    'apos/vfs/stat.h',
    'apos/vfs/vfs.h',
    'apos/wait.h',
]

ARCHS = ['i586', 'x86_64', 'riscv64']


def main(argv):
  parser = argparse.ArgumentParser()
  parser.add_argument("--cross",
                      required=True,
                      help="Prefix of cross directory to install headers into")
  args = parser.parse_args()

  for arch in ARCHS:
    install_dir = os.path.join(args.cross, f'{arch}-pc-apos', 'include')
    for header in HEADERS:
      src = os.path.join(os.path.dirname(__file__), header)
      dst = os.path.join(install_dir, header)
      print(f'Copying: {src} to {dst}')
      shutil.copyfile(src, dst)


if __name__ == '__main__':
  main(sys.argv)
