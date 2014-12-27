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

#ifndef APOO_USER_INCLUDE_APOS_WAIT_H
#define APOO_USER_INCLUDE_APOS_WAIT_H

#define WUNTRACED 1
#define WCONTINUED 2

#define WIFEXITED(x) ((x & 0xF80) == 0)
#define WEXITSTATUS(x) (x & 0x7F)
#define WIFSIGNALED(x) (x & 0x80)
#define WTERMSIG(x) WEXITSTATUS(x)
#define WIFSTOPPED(x) (x & 0x100)
#define WSTOPSIG(x) WTERMSIG(x)
#define WIFCONTINUED(x) (x & 0x200)

#endif
