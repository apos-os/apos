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

#include "proc/group.h"

#include "common/errno.h"
#include "proc/process.h"

pid_t getpgid(pid_t pid) {
  if (pid < 0 || pid >= PROC_MAX_PROCS) {
    return -EINVAL;
  }
  process_t* proc = (pid == 0) ? proc_current() : proc_get(pid);
  if (!proc) {
    return -ESRCH;
  }

  return proc->pgroup;
}
