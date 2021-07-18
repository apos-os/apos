// Copyright 2021 Andrew Oates.  All Rights Reserved.
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
#ifndef APOO_PROC_USER_THREAD_H
#define APOO_PROC_USER_THREAD_H

#include "common/types.h"
#include "proc/load/load.h"
#include "user/include/apos/thread.h"

// Create a userspace-visible kernel thread in the current process.  It will
// start executing in userspace at the given address and using the given stack;
// the state of the processor is otherwise unspecified.
//
// Returns 0 on success, or -errno.  On success, returns the ID of the new
// thread in `id`.
//
// TODO(aoates): consider switching this to a different type than void* once a
// more rigorous userspace-address/ABI system is in place.
int proc_thread_create_user(apos_uthread_id_t* id, void* stack, void* entry);

// Very thin wrapper around proc_thread_exit() that doesn't take an argument.
// TODO(aoates): make this return void.
int proc_thread_exit_user(void) __attribute__((noreturn));

// Send a signal to a particular thread.
int proc_thread_kill_user(const apos_uthread_id_t* id, int sig);

// Get the ID of the current thread.
// TODO(aoates): make this return void.
int proc_thread_self(apos_uthread_id_t* id);

#endif
