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

#include "common/hash.h"
#include "common/klog.h"

long do_syscall_test(long arg1, long arg2, long arg3, long arg4, long arg5,
                     long arg6) {
  const long args[] = { arg1, arg2, arg3, arg4, arg5, arg6 };
  uint32_t hash = fnv_hash_array(args, sizeof(long) * 6);
  klogf("SYSCALL(test): %ld, %ld, %ld, %ld, %ld, %ld --> %d\n",
        arg1, arg2, arg3, arg4, arg5, arg6, hash);
  return hash;
}
