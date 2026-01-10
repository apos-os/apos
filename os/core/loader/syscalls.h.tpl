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

#ifndef APOO_OS_CORE_LOADER_SYSCALLS_H
#define APOO_OS_CORE_LOADER_SYSCALLS_H

#include <sys/types.h>

{# Declarations of syscalls for ld usage -#}
{# PY_IMPORT syscall/syscall_list.py -#}
{% import "syscall/common_macros.tpl" as common %}
{% import "os/core/loader/syscall_list.tpl" as ld_syscall_list %}

{# Generate declarations for each syscall needed in ld -#}
// Manual wrappers around the syscalls used by the loader code, since it doesn't
// link against newlib/libc.  Unlike the stdlib variants, these return -error
// rather than setting errno.
{% for syscall in SYSCALLS if syscall.name in ld_syscall_list.ld_syscalls %}
{{ common.syscall_decl(syscall.native(), 'ld_') }};
{% endfor %}

#endif
