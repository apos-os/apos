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

#include "proc/user_prepare.h"

#include "proc/signal/signal.h"

void proc_prep_user_return(user_context_t (*context_fn)(void*), void* arg) {
  if (proc_assign_pending_signals()) {
    user_context_t context = context_fn(arg);
    proc_dispatch_pending_signals(&context);
  }
}
