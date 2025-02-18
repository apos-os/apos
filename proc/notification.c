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

#include "proc/notification.h"

#include "common/kassert.h"
#include "proc/scheduler.h"

void ntfn_init(notification_t* n) {
  n->status = false;
  kmutex_init(&n->mu);
  kthread_queue_init(&n->queue);
}

void ntfn_notify(notification_t* n) {
  kmutex_lock(&n->mu);
  KASSERT_MSG(!n->status, "notification already notified");
  n->status = true;
  scheduler_wake_all(&n->queue);
  kmutex_unlock(&n->mu);
}

bool ntfn_has_been_notified(notification_t* n) {
  kmutex_lock(&n->mu);
  int result = n->status;
  kmutex_unlock(&n->mu);
  return result;
}

void ntfn_await(notification_t* n) {
  bool result = ntfn_await_with_timeout(n, -1);
  KASSERT(result);
}

bool ntfn_await_with_timeout(notification_t* n, int timeout_ms) {
  kmutex_lock(&n->mu);
  while (!n->status) {
    int result = scheduler_wait_on_locked(&n->queue, timeout_ms, &n->mu);
    KASSERT(result != SWAIT_INTERRUPTED);
    if (result == SWAIT_TIMEOUT) {
      kmutex_unlock(&n->mu);
      return false;
    }
  }
  kmutex_unlock(&n->mu);
  return true;
}
