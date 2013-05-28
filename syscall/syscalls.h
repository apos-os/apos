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

// List of syscalls.  Manually generated from syscall/syscalls.h.tpl.
//
// To regenerate:
//   util/tpl_gen.py syscall/syscalls.h.tpl > syscall/syscalls.h
#ifndef APOO_SYSCALL_SYSCALLS_H
#define APOO_SYSCALL_SYSCALLS_H

// All syscalls and their numbers.
#define SYS_SYSCALL_TEST 0
#define SYS_OPEN 1
#define SYS_CLOSE 2
#define SYS_MKDIR 3
#define SYS_MKNOD 4
#define SYS_RMDIR 5
#define SYS_UNLINK 6
#define SYS_READ 7
#define SYS_WRITE 8
#define SYS_SEEK 9
#define SYS_GETDENTS 10
#define SYS_GETCWD 11
#define SYS_CHDIR 12
#define SYS_FORK 13
#define SYS_EXIT 14
#define SYS_EXECVE 15
#define SYS_GETPID 16
#define SYS_GETPPID 17
#define SYS_ISATTY 18

#endif
