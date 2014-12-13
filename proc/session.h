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

#ifndef APOO_PROC_SESSION_H
#define APOO_PROC_SESSION_H

#include "user/include/apos/posix_types.h"

#define PROC_SESSION_NO_CTTY -1

typedef struct {
  // The ID of the session's controlling terminal, or -1 if none.
  int ctty;
} proc_session_t;

// Create a new session, as per setsid(2).
pid_t proc_setsid(void);

// Return the process group ID of the session leader of the given process.
pid_t proc_getsid(pid_t pid);

// Return the given session, or NULL if it doesn't exist.
proc_session_t* proc_session_get(sid_t sid);

#endif
