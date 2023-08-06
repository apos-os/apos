// Copyright 2021 Andrew Oates.  All Rights Reserved.
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

#include "os/common/apos_klog.h"

#define _GNU_SOURCE 1  // Get vasprintf

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef APOS_NATIVE_TARGET
# define apos_klog(x) printf("%s\n", (x))
#else
# include <apos/syscall_decls.h>
#endif

void apos_klogf(const char* fmt, ...) {
  va_list args;
  va_start(args, fmt);
  char* buf = NULL;
  vasprintf(&buf, fmt, args);
  if (buf) {
    apos_klog(buf);
    free(buf);
  } else {
    apos_klog("<unable to log>\n");
  }
  va_end(args);
}
