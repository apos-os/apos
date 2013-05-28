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

#ifndef APOO_PROC_EXEC_H
#define APOO_PROC_EXEC_H

// Attempt to load into user-space and execute the binary at the given path.
//
// The cleanup function will be called just before entering user mode, and can
// be used to clean up kernel memory allocated for this call (e.g. argv and
// envp)
int do_execve(const char* path, char* const argv[], char* const envp[],
              void (*cleanup)(const char* path,
                              char* const argv[],
                              char* const envp[],
                              void* arg),
              void* cleanup_arg);

#endif
