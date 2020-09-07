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

#ifndef APOO_SYSCALL_FORK_H
#define APOO_SYSCALL_FORK_H

#include "proc/process.h"

// Syscall version of proc_fork().  Extracts the current syscall context, and
// uses that to trampoline back into userspace at the same point in the child
// process.
kpid_t proc_fork_syscall(void);

#endif
