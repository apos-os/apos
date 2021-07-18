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

#ifndef APOO_PROC_EXIT_H
#define APOO_PROC_EXIT_H

// Exit the current process, recording the given exit status.
//
// This signals all other threads to terminate and begins the teardown process,
// but the process itself won't be terminated until all threads have terminated.
//
// In certain circumstances, proc_exit() itself may never be called, only
// proc_finish_exit() (see below).
//
// This function will not return.
void proc_exit(int status) __attribute__((noreturn));

// Finalize the exiting process.  Must be called from the last thread running
// the process once all others have exited.
//
// Do not use outside proc code.
void proc_finish_exit(void) __attribute__((noreturn));

#endif
