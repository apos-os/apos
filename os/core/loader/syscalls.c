// Copyright 2025 Andrew Oates.  All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// Manual wrappers for the syscalls we need, since we don't link libc/newlib.
#include <apos/syscall.h>
#include <apos/syscalls.h>

#include "os/core/loader/syscalls.h"

int ld_open(const char* path, int flags, apos_mode_t mode) {
  int result;
  do {
    result = do_syscall(SYS_OPEN, (long)path, (long)flags, (long)mode, 0, 0, 0);

  } while (result == -EINTR_RESTART);
  return result;
}

int ld_close(int fd) {
  int result;
  do {
    result = do_syscall(SYS_CLOSE, (long)fd, 0, 0, 0, 0, 0);

  } while (result == -EINTR_RESTART);
  return result;
}

ssize_t ld_read(int fd, void* buf, size_t count) {
  ssize_t result;
  do {
    result = do_syscall(SYS_READ, (long)fd, (long)buf, (long)count, 0, 0, 0);

  } while (result == -EINTR_RESTART);
  return result;
}

ssize_t ld_write(int fd, const void* buf, size_t count) {
  ssize_t result;
  do {
    result = do_syscall(SYS_WRITE, (long)fd, (long)buf, (long)count, 0, 0, 0);

  } while (result == -EINTR_RESTART);
  return result;
}

apos_off_t ld_lseek(int fd, apos_off_t offset, int whence) {
  apos_off_t result;
  do {
    result =
        do_syscall(SYS_LSEEK, (long)fd, (long)offset, (long)whence, 0, 0, 0);

  } while (result == -EINTR_RESTART);
  return result;
}

int ld_exit(int status) {
  int result;
  result = do_syscall(SYS_EXIT, (long)status, 0, 0, 0, 0, 0);

  return result;
}

int ld_mmap(void* addr_inout, size_t length, int prot, int flags, int fd,
            apos_off_t offset) {
  int result;
  do {
    result = do_syscall(SYS_MMAP, (long)addr_inout, (long)length, (long)prot,
                        (long)flags, (long)fd, (long)offset);

  } while (result == -EINTR_RESTART);
  return result;
}
