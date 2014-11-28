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

{# PY_IMPORT syscall/syscall_list.py #}
{% import "syscall/common_macros.tpl" as common %}
// Declarations of all syscalls as they're named in userspace.
#ifndef APOO_USER_SYSCALLS_DECLS_H
#define APOO_USER_SYSCALLS_DECLS_H

{{ common.include_headers(SYSCALLS, 'user_header') }}

// Declare the userspace functions.
{% for syscall in SYSCALLS if "L3" in syscall.stubs_to_generate %}
{{ common.syscall_decl(syscall, "") }};
{% endfor %}

#endif
