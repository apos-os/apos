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

// Kernel process management.
#ifndef APOO_PROCESS_H
#define APOO_PROCESS_H

#include "common/list.h"
#include "proc/alarm.h"
#include "proc/kthread.h"
#include "proc/kthread-internal.h"
#include "proc/signal/signal.h"

#define PROC_MAX_PROCS 256
#define PROC_MAX_FDS 32
#define PROC_UNUSED_FD -1

struct vnode;

// Process state.
typedef enum {
  PROC_INVALID,
  PROC_RUNNING,
  PROC_ZOMBIE,
} proc_state_t;

// Note: any fields added here (and potentially in kthread_t) must be properly
// handled in fork(), execve(), and exit().
struct process {
  pid_t id;  // Index into global process table.
  proc_state_t state;
  kthread_t thread;  // Main process thread.
  int exit_status;

  // File descriptors.  Indexes into the global file table.
  int fds[PROC_MAX_FDS];

  // The current working directory of the process.
  struct vnode* cwd;

  // List of vm_area_t's of the mmap'd areas in the current process.
  list_t vm_area_list;

  page_dir_ptr_t page_directory;

  // Set of pending signals.
  sigset_t pending_signals;

  // Current signal dispositions.
  sigaction_t signal_dispositions[SIGMAX + 1];

  // Pending alarm, if any.
  proc_alarm_t alarm;

  // Real, effective, and saved uid and gid.
  uid_t ruid;
  gid_t rgid;
  uid_t euid;
  gid_t egid;
  uid_t suid;
  gid_t sgid;

  // Parent process.
  process_t* parent;

  // Child processes (alive and zombies).
  list_t children_list;

  // Link on parent's children list.
  list_link_t children_link;

  // Wait queue for the parent thread wait()'ing.
  kthread_queue_t wait_queue;
};

// Initialize the process table, and create the first process (process 0) from
// the current thread.
//
// Initialization has two stages.  Stage 1, which has no init
// dependencies, creates the initial process and
// minimally initializes it.
//
// Stage 2 finishes initializing the root process.

// Minimally initialize the root process.  After proc_init_stage1, the
// vm_area_list may be modified, but nothing else.
void proc_init_stage1(void);

// Finish initializing the root process (except for the cwd).
//
// REQUIRES: kthread_init() and scheduler_init().
void proc_init_stage2(void);

// Return the current process descriptor.
process_t* proc_current(void);

// Return the process_t with the given ID, or NULL if there is none.
process_t* proc_get(pid_t id);

#endif
