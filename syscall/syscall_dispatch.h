// Copyright 2023 Andrew Oates.  All Rights Reserved.
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

#ifndef APOO_SYSCALL_SYSCALL_DISPATCH_H
#define APOO_SYSCALL_SYSCALL_DISPATCH_H

long syscall_dispatch(long syscall_number, long arg1, long arg2, long arg3,
                      long arg4, long arg5, long arg6);

#endif
