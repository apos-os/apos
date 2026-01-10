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
//
// Manual wrappers for the syscalls we need, since we don't link libc/newlib.
#include "os/core/loader/syscalls.h"

#include <apos/syscall.h>
#include <apos/syscalls.h>

{# Declarations of syscalls for ld usage -#}
{# PY_IMPORT syscall/syscall_list.py -#}
{% import "syscall/common_macros.tpl" as common %}
{% import "os/core/loader/syscall_list.tpl" as ld_syscall_list %}

{# Generate the LD stubs only for the functions we care about. -#}
{% for syscall in SYSCALLS if syscall.name in ld_syscall_list.ld_syscalls %}
{% set syscall = syscall.native() %}
{{ common.syscall_decl(syscall, 'ld_') }} {
  {{ common.syscall_impl_body(syscall) }}
}

{% endfor %}
