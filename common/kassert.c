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

#include "common/kassert.h"

#include "common/klog.h"

void die(const char* msg) {
  klog("PANIC: ");
  if (msg) {
    klog(msg);
    klog("\n");
  } else {
    klog("<unknown reason :(>\n");
  }
  __asm__ __volatile__ (
      "cli\n\t"
      "hlt\n\t");
}

void kassert(int x) {
  kassert_msg(x, 0);
}

void kassert_msg(int x, const char* msg) {
  if (!x) {
    die(msg);
  }
}
