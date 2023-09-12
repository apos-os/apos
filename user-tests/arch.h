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

#ifndef APOO_USER_TESTS_ARCH_H
#define APOO_USER_TESTS_ARCH_H

#if defined(__i386)
#define ARCH_X86
#define ARCH_X86_32
#define ARCH_IS_64_BIT 0
#define ARCH_HAS_SIGFPE 1
#endif

#if defined(__x86_64)
#define ARCH_X86
#define ARCH_X86_64
#define ARCH_IS_64_BIT 1
#define ARCH_HAS_SIGFPE 1
#endif

#if defined(__riscv) && __riscv_xlen == 64
#define ARCH_RISCV
#define ARCH_RISCV_64
#define ARCH_IS_64_BIT 1
#define ARCH_HAS_SIGFPE 0
#endif

#endif
