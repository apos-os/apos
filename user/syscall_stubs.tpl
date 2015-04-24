{#
 # Copyright 2014 Andrew Oates.  All Rights Reserved.
 #
 # Licensed under the Apache License, Version 2.0 (the "License");
 # you may not use this file except in compliance with the License.
 # You may obtain a copy of the License at
 #
 #     http://www.apache.org/licenses/LICENSE-2.0
 #
 # Unless required by applicable law or agreed to in writing, software
 # distributed under the License is distributed on an "AS IS" BASIS,
 # WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 # See the License for the specific language governing permissions and
 # limitations under the License.
 #-}

{# Implementation of syscalls in user-mode. -#}
{# PY_IMPORT syscall/syscall_list.py #}
{% import "syscall/common_macros.tpl" as common %}

{# Casts a syscalls arguments from the actual type to long. #}
{% macro cast_args(args) -%}
{% for arg_num in range(MAX_ARGS) -%}
{% if arg_num < args | length -%}
(long){{ args[arg_num].name }}
{%- else -%}
0
{%- endif -%}
{% if not loop.last %}, {% endif %}
{%- endfor %}
{%- endmacro %}

{#- Implement a user-space syscall. #}
{%- macro syscall_impl(syscall) -%}
static inline {{ common.syscall_decl(syscall, '_do_') }} {
  {{ syscall.return_type }} result;
  {% if syscall.can_fail -%}
  do {
  {% endif -%}

  result = do_syscall({{ common.syscall_constant(syscall) }}, {{ cast_args(syscall.args) }});

  {% if syscall.can_fail -%}
  } while (result == -EINTR_RESTART);
  {% endif -%}
  return result;
}
{%- endmacro %}

#if __APOS_BUILDING_IN_TREE__
#  include "user/include/apos/syscall.h"
#  include "user/include/apos/syscalls.h"
#else
#  include <apos/syscall.h>
#  include <apos/syscalls.h>
#endif

{{ common.include_headers(SYSCALLS, 'user_header') }}

{# First, generate L1 stubs for most syscalls. #}
{% for syscall in SYSCALLS if 'L1' in syscall.stubs_to_generate %}
{{ syscall_impl(syscall) }}

{% endfor %}
