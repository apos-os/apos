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

// open needs a special stub to handle the varargs third argument.
int open(const char* path, int flags, ...) {
  mode_t mode = 0;
  if (flags & O_CREAT) {
    va_list args;
    va_start(args, flags);
    mode = va_arg(args, mode_t);
    va_end(args);
  }
  return _do_open(path, flags, mode);
}

__attribute__((noreturn)) void _exit(int status) {
  _do_exit(status);
  // Should never get here.  Loop to make the compiler happy.
  while (1) {}
}

char* getcwd(char* buf, size_t size) {
  int result = _do_getcwd(buf, size);
  if (result) {
    // TODO(aoates): set errno
    return NULL;
  }
  return buf;
}
