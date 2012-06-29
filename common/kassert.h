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

#ifndef APOO_KASSERT_H
#define APOO_KAS

#define STR2(x) #x
#define STR(x) STR2(x)

#define KASSERT(cond) do { \
  kassert_msg((cond), "assertion failed: " #cond " (" __FILE__ ":" STR(__LINE__) ")\n"); \
} while(0)

// Kills the kernel, logging the given message first.
void die(const char* msg);

// Calls die() if x is zero.
void kassert(int x);
void kassert_msg(int x, const char* msg);

#endif
