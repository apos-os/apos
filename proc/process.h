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
#include "memory/memory.h"
#include "proc/alarm.h"
#include "proc/kthread.h"
#include "proc/kthread-queue.h"
#include "proc/load/load.h"
#include "proc/pmutex.h"
#include "proc/spinlock.h"
#include "proc/thread_annotations.h"
#include "user/include/apos/posix_signal.h"
#include "user/include/apos/resource.h"
#include "vfs/file.h"

#define PROC_MAX_PROCS 256
#define PROC_MAX_FDS 32
#define PROC_UNUSED_FD -1

// Lock that protects the process table, process group table, and session table.
extern kspinlock_t g_proc_table_lock;

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
// TODO(aoates): update all fields here to be properly prempt-safe.
typedef struct process {
  uint32_t guid;
  kpid_t id;  // Index into global process table.
  pmutex_t mu;
  kspinlock_t spin_mu ACQUIRED_AFTER(&mu) ACQUIRED_AFTER(g_proc_table_lock);
  proc_state_t state GUARDED_BY(&spin_mu);
  list_t threads GUARDED_BY(&spin_mu);  // All process threads.
  int exit_status GUARDED_BY(&spin_mu);  // Exit status if PROC_ZOMBIE, or PROC_STOPPED.
  bool exiting GUARDED_BY(&spin_mu);  // Whether the process is exiting.

  // File descriptors.  Indexes into the global file table.
  fd_t fds[PROC_MAX_FDS] GUARDED_BY(&mu);

  // The current working directory of the process.
  struct vnode* cwd GUARDED_BY(&mu);

  // List of vm_area_t's of the mmap'd areas in the current process.
  list_t vm_area_list GUARDED_BY(&mu);

  page_dir_ptr_t page_directory;  // const after construction

  // Set of pending signals.
  ksigset_t pending_signals GUARDED_BY(&spin_mu);

  // Current signal dispositions.
  ksigaction_t signal_dispositions[APOS_SIGMAX + 1] GUARDED_BY(&spin_mu);

  // Pending alarm, if any.
  proc_alarm_t alarm GUARDED_BY(&spin_mu);

  // Real, effective, and saved uid and gid.
  // These must be compared across processes, and are not expected to change
  // frequently, so we lock them with g_proc_table_lock rather than per-process
  // locks for lock-ordering simplicity.
  kuid_t ruid GUARDED_BY(g_proc_table_lock);
  kgid_t rgid GUARDED_BY(g_proc_table_lock);
  kuid_t euid GUARDED_BY(g_proc_table_lock);
  kgid_t egid GUARDED_BY(g_proc_table_lock);
  kuid_t suid GUARDED_BY(g_proc_table_lock);
  kgid_t sgid GUARDED_BY(g_proc_table_lock);

  // The current process group.
  kpid_t pgroup GUARDED_BY(g_proc_table_lock);

  // Link on the process group list.
  list_link_t pgroup_link GUARDED_BY(g_proc_table_lock);

  // The process's umask.
  kmode_t umask GUARDED_BY(&mu);

  // Has this process exec()'d since it was created.
  bool execed GUARDED_BY(&mu);

  // User-mode architecture, once determined (e.g. by exec()).
  // Non-process-thread readers must lock |mu|.
  bin_arch_t user_arch;  // const except during exec()

  // Parent process.  Cannot be modified without holding the old and new
  // parent's mutexs as well.
  struct process* parent GUARDED_BY(&mu);

  // Child processes (alive and zombies).
  list_t children_list GUARDED_BY(&mu);

  // Link on parent's children list.
  list_link_t children_link GUARDED_BY(&mu);

  // Wait queue for the parent thread wait()'ing.
  kthread_queue_t wait_queue;

  // Wait queue for the process's threads if the process is STOPPED.
  kthread_queue_t stopped_queue;

  // Wait queue that is notified whenever the set of threads in the process
  // changes (thread exit or start).
  kthread_queue_t thread_change_queue;

  // Resource limits.
  struct apos_rlimit limits[APOS_RLIMIT_NUM_RESOURCES];

  refcount_t refcount;
} process_t;

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

// Return the current process descriptor.  Does NOT increment the refcount.
process_t* proc_current(void);

// Return the process_t with the given ID, or NULL if there is none.  Does not
// increment the refcount, and should only be used by code that knows the
// process will continue to live (such a single-threaded test code).
process_t* proc_get(kpid_t id) EXCLUDES(g_proc_table_lock);
process_t* proc_get_locked(kpid_t id) REQUIRES(g_proc_table_lock);

// As above, but adds a refcount to the process --- the caller must call
// proc_put() on it later.
process_t* proc_get_ref(kpid_t id) EXCLUDES(g_proc_table_lock);

void proc_put(process_t* proc);

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

// Returns the state of the process.
proc_state_t proc_state(kpid_t pid);

// Helper to lock both a process and its parent.  Returns the process's parent,
// with both the parent and the process itself locked.  The caller MUST use the
// returned parent, not one read earlier, as the process could be reparented
// during this call.
//
// Returns a reference on the parent that must be proc_put() by the caller.
process_t* proc_get_and_lock_parent(process_t* child) ACQUIRE(child->mu);

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
