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
#ifndef APOO_PROC_NOTIFICATION_H
#define APOO_PROC_NOTIFICATION_H

#include <stdbool.h>

#include "proc/kthread.h"

// A basic notification, inspired by absl::Notification.
struct notification;
typedef struct notification notification_t;

void ntfn_init(notification_t* n);
void ntfn_notify(notification_t* n);
bool ntfn_has_been_notified(notification_t* n);
void ntfn_await(notification_t* n);
bool ntfn_await_with_timeout(notification_t* n, int timeout_ms);

struct notification {
  bool status;
  kmutex_t mu;
  kthread_queue_t queue;
};

#endif
