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

// Common types required by POSIX to be defined in <sys/types.h>.
#ifndef APOO_USER_POSIX_TYPES_H
#define APOO_USER_POSIX_TYPES_H

// Process ID.
typedef int pid_t;
typedef int sid_t;

// User and group IDs.
typedef int uid_t;
typedef int gid_t;

typedef int mode_t;

typedef int blksize_t;
typedef int blkcnt_t;

typedef long off_t;
typedef unsigned long ino_t;
typedef unsigned short nlink_t;

typedef long time_t;
typedef unsigned long useconds_t;
typedef long suseconds_t;

typedef long ssize_t;

#endif
