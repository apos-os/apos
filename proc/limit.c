// Copyright 2015 Andrew Oates.  All Rights Reserved.
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

#include "proc/limit.h"

#include "proc/process.h"
#include "proc/user.h"

int proc_getrlimit(int resource, struct rlimit* lim) {
  if (resource < 0 || resource >= RLIMIT_NUM_RESOURCES)
    return -EINVAL;

  *lim = proc_current()->limits[resource];
  return 0;
}

int proc_setrlimit(int resource, const struct rlimit* lim) {
  if (resource < 0 || resource >= RLIMIT_NUM_RESOURCES)
    return -EINVAL;

  if (lim->rlim_cur > lim->rlim_max)
    return -EINVAL;

  if (lim->rlim_max > proc_current()->limits[resource].rlim_max &&
      !proc_is_superuser(proc_current()))
    return -EPERM;

  // TODO(aoates): check if new limit is above current usage.

  proc_current()->limits[resource] = *lim;
  return 0;
}
