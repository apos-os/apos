// Copyright 2024 Andrew Oates.  All Rights Reserved.
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

#ifndef APOO_PROC_PREEMPTION_HOOK_H
#define APOO_PROC_PREEMPTION_HOOK_H

// A number between 0 and 10 to dictate the amount of time option
// force-preemption hooks are taken.  Set to 0 to disable (production code).  10
// will preempt on most hooks (extremely high overhead).  Even at 10, not all
// hooks will be taken, to ensure we avoid weird aliasing effects where buggy
// racing threads preempt back and forth every time and avoid the actual race.
//
// Factors are separate for each data structure.  Different modules will use the
// data structures differently, so these should be tested separately.
#define PREEMPTION_INDUCE_LEVEL_LIST 0
#define PREEMPTION_INDUCE_LEVEL_HTBL 0
#define PREEMPTION_INDUCE_LEVEL_CIRCBUF 0

// Preempt the current thread IF preemption is enabled.  Otherwise, a no-op.
// Not guaranteed to actually preempt --- should be inserted into key code
// places to stress-test preemption-safety, but cannot be used for correctness.
void sched_preempt_me(int level);

#endif
