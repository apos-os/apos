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
{% import "syscall/syscall_dmz_macros.tpl" as dmz_macros %}
#include "common/errno.h"
#include "common/kstring.h"
#include "memory/kmalloc.h"
#include "syscall/dmz.h"
#include "syscall/wrappers32.h"

{{ common.include_headers(SYSCALLS, 'header') }}

// Semi-arbitrary limit on the size of buffers that can be passed to/from
// syscalls, to prevent us trying to allocate huge amounts of memory on behalf
// of bogus syscalls.  Must be at most UINT32_MAX / 2 to catch negative sizes.
#define DMZ_MAX_BUFSIZE (PAGE_SIZE * 256)
_Static_assert(DMZ_MAX_BUFSIZE < UINT32_MAX / 2, "DMZ_MAX_BUFSIZE too large");

{% for syscall in SYSCALLS -%}
{{ dmz_macros.syscall_dmz(syscall) }}

{% if syscall.needs_32bit_conv %}
{{ dmz_macros.syscall_dmz(syscall.native()) }}
{% endif %}

{% endfor %}
