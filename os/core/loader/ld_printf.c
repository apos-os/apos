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
#include "os/core/loader/ld_printf.h"

#include "os/core/loader/syscalls.h"

/*************************************/
/* Start implementation of kprintf.c */
/*************************************/
// For ssize_t
#include <sys/types.h>

#include "os/core/loader/ld_string.h"  // IWYU pragma: keep

#define KASSERT(x)
#define klog(x)
#define klogm(...)
#define klogfm(...)

#include "common/kprintf.c"
/***********************************/
/* End implementation of kprintf.c */
/***********************************/

// TODO(aoates): change the default to zero.
static int g_ld_log_level = 10;

int ld_log_level(void) {
  return g_ld_log_level;
}

int ld_printf(const char* fmt, ...) {
  va_list args;
  va_start(args, fmt);
  const int kBufLen = 300;
  char buf[kBufLen];
  int len = kvsnprintf(buf, kBufLen, fmt, args);
  va_end(args);
  ld_write(1, buf, len);
  return len;
}
