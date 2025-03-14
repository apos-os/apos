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

bool proc_is_superuser(const process_t* proc) {
  kspin_lock(&g_proc_table_lock);
  bool result = proc_is_superuser_locked(proc);
  kspin_unlock(&g_proc_table_lock);
  return result;
}

bool proc_is_superuser_locked(const process_t* proc) {
  return proc->euid == SUPERUSER_UID;
}

int setuid(kuid_t uid) {
  int result = 0;
  kspin_lock(&g_proc_table_lock);
  if (proc_is_superuser_locked(proc_current())) {
    proc_current()->ruid = uid;
    proc_current()->euid = uid;
    proc_current()->suid = uid;
  } else if (uid == proc_current()->ruid || uid == proc_current()->suid) {
    proc_current()->euid = uid;
  } else {
    result = -EPERM;
  }
  kspin_unlock(&g_proc_table_lock);

  return result;
}

int setgid(kgid_t gid) {
  int result = 0;
  kspin_lock(&g_proc_table_lock);
  if (proc_is_superuser_locked(proc_current())) {
    proc_current()->rgid = gid;
    proc_current()->egid = gid;
    proc_current()->sgid = gid;
  } else if (gid == proc_current()->rgid || gid == proc_current()->sgid) {
    proc_current()->egid = gid;
  } else {
    result = -EPERM;
  }
  kspin_unlock(&g_proc_table_lock);

  return result;
}

kuid_t getuid(void) {
  kspin_lock(&g_proc_table_lock);
  kuid_t result = proc_current()->ruid;
  kspin_unlock(&g_proc_table_lock);
  return result;
}

kgid_t getgid(void) {
  kspin_lock(&g_proc_table_lock);
  kgid_t result = proc_current()->rgid;
  kspin_unlock(&g_proc_table_lock);
  return result;
}

int seteuid(kuid_t uid) {
  int result = 0;
  kspin_lock(&g_proc_table_lock);
  if (proc_is_superuser_locked(proc_current()) || uid == proc_current()->ruid ||
      uid == proc_current()->suid) {
    proc_current()->euid = uid;
  } else {
    result = -EPERM;
  }
  kspin_unlock(&g_proc_table_lock);
  return result;
}

int setegid(kgid_t gid) {
  int result = 0;
  kspin_lock(&g_proc_table_lock);
  if (proc_is_superuser_locked(proc_current()) || gid == proc_current()->rgid ||
      gid == proc_current()->sgid) {
    proc_current()->egid = gid;
  } else {
    result = -EPERM;
  }
  kspin_unlock(&g_proc_table_lock);
  return result;
}

kuid_t geteuid(void) {
  kspin_lock(&g_proc_table_lock);
  kuid_t result = proc_current()->euid;
  kspin_unlock(&g_proc_table_lock);
  return result;
}

kgid_t getegid(void) {
  kspin_lock(&g_proc_table_lock);
  kgid_t result = proc_current()->egid;
  kspin_unlock(&g_proc_table_lock);
  return result;
}

int setreuid(kuid_t ruid, kuid_t euid) {
  kspin_lock(&g_proc_table_lock);
  const int super = proc_is_superuser_locked(proc_current());
  const kuid_t old_ruid = proc_current()->ruid;
  const kuid_t old_euid = proc_current()->euid;
  const kuid_t old_suid = proc_current()->suid;
  kuid_t new_ruid = old_ruid;
  kuid_t new_euid = old_euid;
  if (ruid != -1 && ruid != old_ruid) {
    if (super || ruid == old_euid || ruid == old_suid) {
      new_ruid = ruid;
    } else {
      kspin_unlock(&g_proc_table_lock);
      return -EPERM;
    }
  }
  if (euid != -1 && euid != old_euid) {
    if (super || euid == old_ruid || euid == old_suid) {
      new_euid = euid;
    } else {
      kspin_unlock(&g_proc_table_lock);
      return -EPERM;
    }
  }
  proc_current()->ruid = new_ruid;
  proc_current()->euid = new_euid;
  if (ruid != -1 || (euid != -1 && euid != proc_current()->ruid)) {
    proc_current()->suid = new_euid;
  }
  kspin_unlock(&g_proc_table_lock);
  return 0;
}

int setregid(kgid_t rgid, kgid_t egid) {
  kspin_lock(&g_proc_table_lock);
  const int super = proc_is_superuser_locked(proc_current());
  const kgid_t old_rgid = proc_current()->rgid;
  const kgid_t old_egid = proc_current()->egid;
  const kgid_t old_sgid = proc_current()->sgid;
  kgid_t new_rgid = old_rgid;
  kgid_t new_egid = old_egid;
  if (rgid != -1 && rgid != old_rgid) {
    if (super || rgid == old_egid || rgid == old_sgid) {
      new_rgid = rgid;
    } else {
      kspin_unlock(&g_proc_table_lock);
      return -EPERM;
    }
  }
  if (egid != -1 && egid != old_egid) {
    if (super || egid == old_rgid || egid == old_sgid) {
      new_egid = egid;
    } else {
      kspin_unlock(&g_proc_table_lock);
      return -EPERM;
    }
  }
  proc_current()->rgid = new_rgid;
  proc_current()->egid = new_egid;
  if (rgid != -1 || (egid != -1 && egid != proc_current()->rgid)) {
    proc_current()->sgid = new_egid;
  }
  kspin_unlock(&g_proc_table_lock);
  return 0;
}
