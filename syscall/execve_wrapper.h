// Copyright 2015 Andrew Oates.  All Rights Reserved.
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

#ifndef APOO_SYSCALL_EXECVE_WRAPPER_H
#define APOO_SYSCALL_EXECVE_WRAPPER_H

// Wrapper to manually verify and copy the string tables, and clean up the
// memory before entering the new process.
int execve_wrapper(const char* path_checked,
                   char* const* argv_unchecked,
                   char* const* envp_unchecked);

int execve_wrapper_32(const char* path_checked,
                      char* const* argv_unchecked,
                      char* const* envp_unchecked);
#endif
