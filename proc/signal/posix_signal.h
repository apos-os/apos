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

// Contains the POSIX-required definitions and constants for <signal.h>.  To be
// shared between kernel and user code.
#ifndef APOO_PROC_SIGNAL_POSIX_SIGNAL_H
#define APOO_PROC_SIGNAL_POSIX_SIGNAL_H

#include <stdint.h>

typedef uint32_t sigset_t;

// Signal numbers.
#define SIGNULL 0
#define SIGMIN 1

#define SIGABRT 1
#define SIGALRM 2

#define SIGMAX 2

_Static_assert(sizeof(sigset_t) * 8 >= SIGMAX,
               "sigset_t too small to hold all signals");

#endif
