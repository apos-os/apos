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

{# PY_IMPORT syscall/syscall_list.py #}
{% import "syscall/common_macros.tpl" as common %}

{# Casts a syscalls arguments from the incoming type (long) to required type. #}
{% macro cast_args(args) -%}
{% for arg in args -%}
({{ arg.ctype }})arg{{ loop.index }}{% if not loop.last %}, {% endif %}
{%- endfor %}
{%- endmacro %}

{# Generates the case statement for dispatching a particular syscall. #}
{% macro syscall_dispatch_case(syscall) -%}
case {{ common.syscall_constant(syscall) }}:
  return SYSCALL_DMZ_{{ syscall.name }}({{ cast_args(syscall.args) }});
{%- endmacro %}

#include "common/errno.h"
#include "syscall/syscalls.h"

// Forward declare DMZ functions.
{% for syscall in SYSCALLS %}
long SYSCALL_DMZ_{{ syscall.name }}({{ common.decl_args(syscall.args) }});
{% endfor %}

long syscall_dispatch(long syscall_number, long arg1, long arg2, long arg3,
    long arg4, long arg5, long arg6) {
  switch (syscall_number) {
    {% for syscall in SYSCALLS -%}
    {{ syscall_dispatch_case(syscall) | indent(4) }}

    {% endfor -%}

    default:
      return -ENOTSUP;
  }
}
