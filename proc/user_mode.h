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

#ifndef APOO_PROC_USER_MODE_H
#define APOO_PROC_USER_MODE_H

// Enter user mode using the given stack pointer, and at the given address.
//
// It is the caller's responsibility to set up the stack as needed if this is
// simulating a function call (including arguments, return address, etc).
//
// Will not return.
void user_mode_enter(addr_t stack, addr_t entry);

#endif
