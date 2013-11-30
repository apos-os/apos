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

#include "proc/user.h"

#include "common/errno.h"
#include "proc/process.h"

static inline int is_super(void) {
  return proc_current()->ruid == SUPERUSER_UID ||
      proc_current()->rgid == SUPERUSER_GID;
}

int setuid(uid_t uid) {
  if (is_super()) {
    proc_current()->ruid = uid;
    proc_current()->euid = uid;
    proc_current()->suid = uid;
  } else if (uid == proc_current()->ruid || uid == proc_current()->suid) {
    proc_current()->euid = uid;
  } else {
    return -EPERM;
  }

  return 0;
}

int setgid(gid_t gid) {
  if (is_super()) {
    proc_current()->rgid = gid;
    proc_current()->egid = gid;
    proc_current()->sgid = gid;
  } else if (gid == proc_current()->rgid || gid == proc_current()->sgid) {
    proc_current()->egid = gid;
  } else {
    return -EPERM;
  }

  return 0;
}

uid_t getuid(void) {
  return proc_current()->ruid;
}

gid_t getgid(void) {
  return proc_current()->rgid;
}
