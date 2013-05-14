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
#define SYS_READ 2
#define SYS_WRITE 3

#endif
