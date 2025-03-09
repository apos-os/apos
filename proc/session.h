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

#include "proc/process.h"
#include "proc/thread_annotations.h"
#include "user/include/apos/posix_types.h"

#define PROC_SESSION_NO_CTTY -1

typedef struct {
  // The ID of the session's controlling terminal, or -1 if none.
  int ctty GUARDED_BY(g_proc_table_lock);

  // The foreground process group of the session, or -1 if none.
  kpid_t fggrp GUARDED_BY(g_proc_table_lock);
} proc_session_t;

// Create a new session, as per setsid(2).
kpid_t proc_setsid(void) EXCLUDES(g_proc_table_lock);

// Return the process group ID of the session leader of the given process.
kpid_t proc_getsid(kpid_t pid) EXCLUDES(g_proc_table_lock);

// Returns the session of the given process.
kpid_t proc_getsid_locked(process_t* p) REQUIRES(g_proc_table_lock);

// Return the given session, or NULL if it doesn't exist.
proc_session_t* proc_session_get(ksid_t sid) REQUIRES(g_proc_table_lock);

#endif
