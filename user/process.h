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

#ifndef APOO_USER_FORK_H
#define APOO_USER_FORK_H

// TODO(aoates): Do we want to combine this with the definition in
// proc/process.h?
typedef int pid_t;

pid_t fork();
void _exit(int status);
int execve(const char* path, char* const argv[], char* const envp[]);

#endif
