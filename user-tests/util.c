// Copyright 2022 Andrew Oates.  All Rights Reserved.
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

#include "user-tests/util.h"

#include <assert.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <apos/sleep.h>

bool fntfn_await(const char* name, int timeout_ms) {
  const int kSleepMs = 50;
  while (timeout_ms > 0) {
    int fd = open(name, O_RDWR);
    if (fd >= 0) {
      close(fd);
      return true;
    }
    sleep_ms(kSleepMs);
    timeout_ms -= kSleepMs;
  }
  return false;
}

void fntfn_notify(const char* name) {
  int fd = open(name, O_RDWR | O_CREAT | O_EXCL, S_IRWXU);
  assert(fd >= 0);
  close(fd);
}
