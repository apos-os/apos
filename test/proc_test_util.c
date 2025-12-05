// Copyright 2025 Andrew Oates.  All Rights Reserved.
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
#include "test/proc_test_util.h"

#include "memory/kmalloc.h"
#include "proc/fork.h"
#include "proc/notification.h"
#include "proc/sleep.h"
#include "proc/wait.h"

static void ptu_zombie_child(void* arg) {
  ptu_zombie_t* zombie = (ptu_zombie_t*)arg;
  ntfn_notify(&zombie->child_started);
  zombie->func(zombie->func_arg);
}

static void ptu_zombie_parent(void* arg) {
  ptu_zombie_t* zombie = (ptu_zombie_t*)arg;
  zombie->zombie = proc_fork(&ptu_zombie_child, arg);
  KASSERT(ntfn_await_with_timeout(&zombie->child_started, 1000));
  KASSERT(ntfn_await_with_timeout(&zombie->parent_can_wait, 1000));
  int result = proc_waitpid(zombie->zombie, NULL, 0);
  KASSERT(result == zombie->zombie);
  ntfn_notify(&zombie->parent_wait_done);
}

ptu_zombie_t* ptu_zombie_create(bool uber_zombie, void (*func)(void*),
                                void* arg) {
  ptu_zombie_t* zombie = KMALLOC(ptu_zombie_t);
  zombie->uber_zombie = uber_zombie;
  zombie->func = func;
  zombie->func_arg = arg;
  ntfn_init(&zombie->child_started);
  ntfn_init(&zombie->parent_can_wait);
  ntfn_init(&zombie->parent_wait_done);

  // Spawn the parent and wait for the child to run.
  zombie->parent_pid = proc_fork(&ptu_zombie_parent, zombie);
  KASSERT(zombie->parent_pid >= 0);
  KASSERT(ntfn_await_with_timeout(&zombie->child_started, 1000));

  // If we want an uber-zombie, take an additional reference to the child and
  // let the parent wait.
  if (uber_zombie) {
    zombie->child_proc = proc_get_ref(zombie->zombie);
    ntfn_notify(&zombie->parent_can_wait);
    // Let the parent get stuck.
    KASSERT(!ntfn_await_with_timeout(&zombie->parent_wait_done, 10));
  } else {
    zombie->child_proc = NULL;
  }

  return zombie;
}

void ptu_zombie_cleanup(ptu_zombie_t* zombie) {
  // If we didn't make an uber-zombie, have the parent wait now.
  if (zombie->uber_zombie) {
    proc_put(zombie->child_proc);
  } else {
    ntfn_notify(&zombie->parent_can_wait);
  }
  KASSERT(ntfn_await_with_timeout(&zombie->parent_wait_done, 1000));
  int result = proc_waitpid(zombie->parent_pid, NULL, 0);
  KASSERT(result == zombie->parent_pid);
  kfree(zombie);
}
