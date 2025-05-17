// Copyright 2025 Andrew Oates.  All Rights Reserved.
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

#ifndef APOO_COMMON_PER_CPU_H
#define APOO_COMMON_PER_CPU_H

#include "arch/common/cpu.h"
#include "common/types.h"

// Define a per-cpu variable.  The variable must be accessed with PER_CPU().
#define DECLARE_PER_CPU(_type, _name) \
    _type __percpu_ ## _name __attribute__((section(PER_CPU_SECTION)))

#define _PER_CPU(_var)                            \
  (*((typeof(&_var))((addr_t) & _var - (addr_t) & \
                     _per_cpu_start + _per_cpu_offset[arch_cpu_index()])))

// Access a per-cpu variable.  Must be done in a section with interrupts or
// preemption disabled.
#define PER_CPU(_var) _PER_CPU(__percpu_##_var)

// Implementation details below.

// Section that per-cpu data is placed in.
#define PER_CPU_SECTION ".data.percpu"

// Symbol placed at the start of the per-CPU section.
extern int _per_cpu_start;

// Offsets for each per-cpu section, indexed by CPU index.
extern addr_t _per_cpu_offset[MAX_CPUS];

// Initialize the per-cpu offsets.  Should be called early in the boot process.
void per_cpu_init(void);

#endif
