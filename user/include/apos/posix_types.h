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

// For a given POSIX-required type `foo`, we define three variants:
//  apos_foo --- defined always; used for shared kernel/user code (e.g. syscall
//    stubs, struct definitions).
//  kfoo --- defined only in kernel code, for convenience
//  foo --- defined only in user code
#if __APOS_BUILDING_KERNEL__
# define DEFINE_TYPE(TYPENAME, TYPE) \
    typedef TYPE apos_ ## TYPENAME; \
    typedef apos_ ## TYPENAME k ## TYPENAME
#else
# define DEFINE_TYPE(TYPENAME, TYPE) \
    typedef TYPE apos_ ## TYPENAME; \
    typedef apos_ ## TYPENAME TYPENAME
#endif

// Process ID.
DEFINE_TYPE(pid_t, int);
DEFINE_TYPE(sid_t, int);

// User and group IDs.
DEFINE_TYPE(uid_t, int);
DEFINE_TYPE(gid_t, int);

DEFINE_TYPE(mode_t, int);

DEFINE_TYPE(blksize_t, int);
DEFINE_TYPE(blkcnt_t, int);

DEFINE_TYPE(off_t, long);
DEFINE_TYPE(ino_t, unsigned long);
DEFINE_TYPE(nlink_t, unsigned short);

DEFINE_TYPE(time_t, long);
DEFINE_TYPE(useconds_t, unsigned long);
DEFINE_TYPE(suseconds_t, long);

typedef long ssize_t;

#endif
