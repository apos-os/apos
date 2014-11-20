{#
 # Copyright 2014 Andrew Oates.  All Rights Reserved.
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
 #-}

{# Manually implemented syscall stubs. -#}
#include <stdarg.h>

__attribute__((noreturn)) void _exit(int status) {
  _do_exit(status);
  // Should never get here.  Loop to make the compiler happy.
  while (1) {}
}

char* _getcwd_r(struct _reent* reent_ptr, char* buf, size_t size) {
  int result = _do_getcwd(buf, size);
  if (result) {
    // TODO(aoates): set errno
    return NULL;
  }
  return buf;
}

void* _mmap_r(struct _reent* reent_ptr, void *addr, size_t len, int prot,
              int flags, int fd, off_t offset) {
  int result = _do_mmap(&addr, len, prot, flags, fd, offset);
  if (result) {
    // TODO(aoates): set errno
    return NULL;
  }
  return addr;
}
