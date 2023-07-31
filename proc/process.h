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

#include <stdbool.h>

#include "common/list.h"
#include "proc/alarm.h"
#include "proc/kthread-internal.h"
#include "proc/kthread.h"
#include "proc/load/load.h"
#include "user/include/apos/posix_signal.h"
#include "user/include/apos/resource.h"

#define PROC_MAX_PROCS 256
#define PROC_MAX_FDS 32
#define PROC_UNUSED_FD -1

struct vnode;

// Process state.
typedef enum {
  PROC_INVALID,
  PROC_RUNNING,
  PROC_STOPPED,
  PROC_ZOMBIE,
} proc_state_t;

static inline const char* proc_state_to_string(proc_state_t state);

// Note: any fields added here (and potentially in kthread_t) must be properly
// handled in fork(), execve(), and exit().
struct process {
  uint32_t guid;
  kpid_t id;  // Index into global process table.
  proc_state_t state;
  list_t threads;  // All process threads.
  int exit_status;  // Exit status if PROC_ZOMBIE, or PROC_STOPPED.
  bool exiting;  // Whether the process is exiting.

  // File descriptors.  Indexes into the global file table.
  int fds[PROC_MAX_FDS];

  // The current working directory of the process.
  struct vnode* cwd;

  // List of vm_area_t's of the mmap'd areas in the current process.
  list_t vm_area_list;

  page_dir_ptr_t page_directory;

  // Set of pending signals.
  ksigset_t pending_signals;

  // Current signal dispositions.
  ksigaction_t signal_dispositions[APOS_SIGMAX + 1];

  // Pending alarm, if any.
  proc_alarm_t alarm;

  // Real, effective, and saved uid and gid.
  kuid_t ruid;
  kgid_t rgid;
  kuid_t euid;
  kgid_t egid;
  kuid_t suid;
  kgid_t sgid;

  // The current process group.
  kpid_t pgroup;

  // Link on the process group list.
  list_link_t pgroup_link;

  // The process's umask.
  kmode_t umask;

  // Has this process exec()'d since it was created.
  bool execed;

  // User-mode architecture, once determined (e.g. by exec()).
  bin_arch_t user_arch;

  // Parent process.
  process_t* parent;

  // Child processes (alive and zombies).
  list_t children_list;

  // Link on parent's children list.
  list_link_t children_link;

  // Wait queue for the parent thread wait()'ing.
  kthread_queue_t wait_queue;

  // Wait queue for the process's threads if the process is STOPPED.
  kthread_queue_t stopped_queue;

  // Resource limits.
  struct apos_rlimit limits[APOS_RLIMIT_NUM_RESOURCES];
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
process_t* proc_get(kpid_t id);

// Spawn a new thread associated with the current process.  The new thread
// _must_ either return from the called function, or call proc_thread_exit(),
// _not_ kthread_exit().
//
// Unlike kthread_create(), makes the thread runnable immediately.
int proc_thread_create(kthread_t* thread, void* (*start_routine)(void*),
                       void* arg);

// Exit the current thread, which must have been created with
// proc_thread_create().  If this thread is the last one in the current process,
// exits the process (with status 0).
void proc_thread_exit(void* x) __attribute__((noreturn));

// Implementations.

static inline const char* proc_state_to_string(proc_state_t state) {
  switch (state) {
    case PROC_INVALID: return "INVALID";
    case PROC_RUNNING: return "RUNNING";
    case PROC_STOPPED: return "STOPPED";
    case PROC_ZOMBIE: return "ZOMBIE";
  }
  return "<unknown>";
}

#endif
