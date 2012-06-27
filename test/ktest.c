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

#include "test/ktest.h"

#include "kstring.h"
#include "klog.h"

void KTEST_SUITE_BEGIN(const char* name) {
  klog("\n\nTEST SUITE: ");
  klog(name);
  klog("\n");
  klog("#######################################\n");
}

void KTEST_BEGIN(const char* name) {
  klog("\nTEST: ");
  klog(name);
  klog("\n");
  klog("---------------------------------------\n");
}

void kexpect_(uint32_t cond, const char* name,
              const char* astr, const char* bstr,
              const char* aval, const char* bval,
              const char* opstr,
              const char* file, const char* line) {
  if (cond) {
    klog("[PASSED] ");
    klog(name);
    klog("(");
    klog(astr);
    klog(", ");
    klog(bstr);
    klog(")\n");
  } else {
    klog("[FAILED] ");
    klog(name);
    klog("(");
    klog(astr);
    klog(", ");
    klog(bstr);
    klog(") at ");
    klog(file);
    klog(":");
    klog(line);
    klog(": ");
    klog(aval);
    klog(opstr);
    klog(bval);
    klog("\n");
  }
}
