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

#include "os/common/list.h"

#include <assert.h>

#define APOO_KASSERT_H
#define APOO_PROC_PREEMPTION_HOOK_H
#define PREEMPTION_INDUCE_LEVEL_LIST 0

#define KASSERT_DBG assert
#define KASSERT assert
#define sched_preempt_me()
#include "common/list.c"
