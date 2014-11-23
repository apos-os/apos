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

// Functions for manipulating a process's user and group identity.
#ifndef APOO_PROC_USER_H
#define APOO_PROC_USER_H

#include "proc/process.h"
#include "user/include/apos/posix_types.h"

// The uid and gid of the superuser.
#define SUPERUSER_UID 0
#define SUPERUSER_GID 0

// Returns 1 if the given process is privileged (if the effective uid is the
// superuser).
int proc_is_superuser(const process_t* proc);

// Change the current user ID.  If the superuser, changes the real, effective,
// and saved uids.  Otherwise, changes the effective uid to either the real or
// saved uids.
//
// Returns 0 on success, or -errno on error.
int setuid(uid_t uid);

// Set the current group ID, as per setuid().
int setgid(gid_t gid);

// Return the current real user and group IDs.
uid_t getuid(void);
gid_t getgid(void);

// Set the effective user or group ID.  If the user is not the superuser, the
// new uid/gid must be the real or saved uid/gid.
int seteuid(uid_t uid);
int setegid(gid_t gid);

// Return the current effective user and group IDs.
uid_t geteuid(void);
gid_t getegid(void);

// Set the real and effective user/group IDs, if allowed.
int setreuid(uid_t ruid, uid_t euid);
int setregid(gid_t rgid, gid_t egid);

#endif
