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

#ifndef APOO_PROC_FORK_H
#define APOO_PROC_FORK_H

// The start function of a procedure.
typedef void (*proc_func_t)(void*);

// Fork the current process into a new process with a copy of the current
// address space.  The new process will be identical to the current process,
// except that its main thread will start by calling the given function with the
// given argument.  If the function returns, the new process will exit.
//
// Returns the new process's id on success, or -errno on error.
int proc_fork(proc_func_t start, void* arg);

#endif
