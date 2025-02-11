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
#include "proc/user_thread.h"

#include "arch/proc/user_mode.h"
#include "common/errno.h"
#include "common/kassert.h"
#include "memory/kmalloc.h"
#include "proc/process.h"
#include "proc/signal/signal.h"

typedef struct {
  addr_t stack;
  addr_t entry;
} tramp_args_t;

static void* user_thread_trampoline(void* arg) {
  // TODO(aoates): there are several layers of args structs and trampolines; can
  // we eliminate some?
  tramp_args_t args = *(tramp_args_t*)arg;
  kfree(arg);
  user_mode_enter(args.stack, args.entry);
  die("unreachable");
}

int proc_thread_create_user(apos_uthread_id_t* id_out, void* stack,
                            void* entry) {
  // This isn't great, but easy for now.  Passing the void*s back and forth from
  // userspace is dicey.
  _Static_assert(sizeof(addr_t) >= sizeof(void*), "addr_t can't hold a void*");
  kthread_t kthread_id;
  tramp_args_t* args = (tramp_args_t*)kmalloc(sizeof(tramp_args_t));
  args->entry = (addr_t)entry;
  args->stack = (addr_t)stack;
  int result = proc_thread_create(&kthread_id, &user_thread_trampoline, args);
  if (result) {
    kfree(args);
    return result;
  }

  id_out->_id = kthread_id->id;
  kthread_detach(kthread_id);
  return 0;
}

int proc_thread_exit_user(void) {
  proc_thread_exit(NULL);
}

int proc_thread_kill_user(const apos_uthread_id_t* id, int sig) {
  FOR_EACH_LIST(iter_link, &proc_current()->threads) {
    kthread_data_t* thread =
        LIST_ENTRY(iter_link, kthread_data_t, proc_threads_link);
    if (thread->id == id->_id) {
      return proc_kill_thread(thread, sig);
    }
  }
  return -ESRCH;
}

int proc_thread_self(apos_uthread_id_t* id) {
  id->_id = kthread_current_thread()->id;
  return 0;
}
