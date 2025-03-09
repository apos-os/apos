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

#include "proc/umask.h"
#include "proc/pmutex.h"
#include "proc/process.h"

kmode_t proc_umask(kmode_t cmask) {
  process_t* const me = proc_current();
  pmutex_lock(&me->mu);
  const kmode_t orig_mode = me->umask;
  me->umask = cmask;
  pmutex_unlock(&me->mu);
  return orig_mode;
}
