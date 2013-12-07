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

int proc_is_superuser(const process_t* proc) {
  return proc->euid == SUPERUSER_UID;
}

int setuid(uid_t uid) {
  if (proc_is_superuser(proc_current())) {
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
  if (proc_is_superuser(proc_current())) {
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

int seteuid(uid_t uid) {
  if (proc_is_superuser(proc_current()) || uid == proc_current()->ruid ||
      uid == proc_current()->suid) {
    proc_current()->euid = uid;
    return 0;
  } else {
    return -EPERM;
  }
}

int setegid(gid_t gid) {
  if (proc_is_superuser(proc_current()) || gid == proc_current()->rgid ||
      gid == proc_current()->sgid) {
    proc_current()->egid = gid;
    return 0;
  } else {
    return -EPERM;
  }
}

uid_t geteuid(void) {
  return proc_current()->euid;
}

gid_t getegid(void) {
  return proc_current()->egid;
}

int setreuid(uid_t ruid, uid_t euid) {
  const int super = proc_is_superuser(proc_current());
  if (ruid != -1 && ruid != proc_current()->ruid) {
    if (super) {
      proc_current()->ruid = ruid;
    } else {
      return -EPERM;
    }
  }
  if (euid != -1 && euid != proc_current()->euid) {
    if (super || euid == proc_current()->ruid ||
         euid == proc_current()->suid) {
      proc_current()->euid = euid;
    } else {
      return -EPERM;
    }
  }
  if (ruid != -1 || (euid != -1 && euid != proc_current()->ruid)) {
    proc_current()->suid = proc_current()->euid;
  }
  return 0;
}

int setregid(gid_t rgid, gid_t egid) {
  const int super = proc_is_superuser(proc_current());
  if (rgid != -1 && rgid != proc_current()->rgid) {
    if (super) {
      proc_current()->rgid = rgid;
    } else {
      return -EPERM;
    }
  }
  if (egid != -1 && egid != proc_current()->egid) {
    if (super || egid == proc_current()->rgid ||
         egid == proc_current()->sgid) {
      proc_current()->egid = egid;
    } else {
      return -EPERM;
    }
  }
  if (rgid != -1 || (egid != -1 && egid != proc_current()->rgid)) {
    proc_current()->sgid = proc_current()->egid;
  }
  return 0;
}
