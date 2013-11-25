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

#include "proc/signal/signal.h"

#include "proc/process.h"

int proc_kill(pid_t pid, int sig) {
  if (pid == 0) {
    return -EINVAL;
  }

  process_t* proc = proc_get(pid);
  if (!proc || proc->state != PROC_RUNNING) {
    return -EINVAL;
  }

  if (sig == SIGNULL) {
    return 0;
  }

  return ksigaddset(&proc->pending_signals, sig);
}
