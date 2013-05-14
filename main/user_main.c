// Copyright 2014 Andrew Oates.  All Rights Reserved.
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

// Test user-mode program.
// TODO(aoates): remove when binary loading is supported.

#include "user/fs.h"
#include "user/syscall.h"
#include "user/test.h"

int my_strlen(const char* str) {
  int len = 0;
  while (str[len]) len++;
  return len;
}

void write_all(int fd, const char* str) {
  int len = my_strlen(str);
  while (len > 0) {
    const int result = write(fd, str, len);
    if (result < 0) return;
    len -= result;
    str += result;
  }
}

void user_main() {
  long ret = syscall_test(1, 2, 3, 4, 5, 6);

  const int fd = open("/dev/tty0", O_RDWR);
  if (fd < 0) while (1) {}
  write_all(fd, "In user-mode!\n");

  while (ret) {}
}
