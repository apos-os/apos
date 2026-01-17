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
#include <stdlib.h>
#include <unistd.h>
#include <apos/mmap.h>

__attribute__((noreturn)) void _exit(int status) {
  _do_exit(status);
  // Should never get here.  Loop to make the compiler happy.
  while (1) {}
}

// We need a custom wrapper to return char* rather than error int.
char* _getcwd_r(struct _reent* reent_ptr, char* buf, size_t size) {
  if (!buf) {
    // TODO(aoates): use VFS_MAX_PATH_LENGTH.
    const int kMaxSize = 1000;  // Guess the max size.
    buf = malloc(kMaxSize);
    size = kMaxSize;
  }
  int result = _do_getcwd(buf, size);
  if (result < 0) {
    reent_ptr->_errno = -result;
    return NULL;
  }
  return buf;
}

char* getcwd(char* buf, size_t size) {
  return _getcwd_r(_REENT, buf, size);
}

void* _mmap_r(struct _reent* reent_ptr, void *addr, size_t len, int prot,
              int flags, int fd, off_t offset) {
  int result = _do_mmap(&addr, len, prot, flags, fd, offset);
  if (result) {
    reent_ptr->_errno = -result;
    return MAP_FAILED;
  }
  return addr;
}

void* mmap(void *addr, size_t len, int prot,
    int flags, int fd, off_t offset) {
  return _mmap_r(_REENT, addr, len, prot, flags, fd, offset);
}

unsigned alarm(unsigned seconds) {
  return alarm_ms(seconds * 1000);
}

unsigned int sleep(unsigned int seconds) {
  return sleep_ms(seconds * 1000);
}

// Manual stub to convert from int[2] to int* and mollify GCC's
// array-parameter diagnostic.
int pipe(int fildes[2]) { return _pipe_r(_REENT, fildes); }

int open(const char *path, int oflag, ... ) {
  mode_t mode = 0;
  if (oflag & O_CREAT) {
    va_list args;
    va_start(args, oflag);
    mode = va_arg(args, mode_t);
    va_end(args);
  }
  return _open_r(_REENT, path, oflag, mode);
}

int fcntl(int fd, int cmd, ...) {
  // Note: this is technically undefined behavior, since the caller could be
  // passing a valid cmd/type pair that we don't know about (and isn't an int).
  // But for now, assume the third argument is always an int.mode_t mode = 0;
  va_list args;
  va_start(args, cmd);
  int arg = va_arg(args, int);
  va_end(args);
  return _fcntl_r(_REENT, fd, cmd, arg);
}
