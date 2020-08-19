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

#ifndef APOO_PROC_TCGROUP_H
#define APOO_PROC_TCGROUP_H

#include "proc/process.h"
#include "user/include/apos/posix_types.h"

// The value returned by proc_tcgetpgrp() if there is no foreground process
// group.
#define PROC_NO_FGGRP (PROC_MAX_PROCS + 1)

// Set the foreground process group of the current session, if there is a
// controlling terminal.  fd must point at the controlling terminal.
int proc_tcsetpgrp(int fd, kpid_t pgid);

// Returns the foreground process group of the current session, if there is a
// controlling terminal and foreground process group.  If there is no foregroup
// process group, returns PROC_NO_FGGRP.
int proc_tcgetpgrp(int fd);

// Returns the process group ID of the session leader of the session for whom fd
// points to the controlling terminal.  This is essentially the same as
// getsid(0).
kpid_t proc_tcgetsid(int fd);

#endif
