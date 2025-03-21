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

{# Casts a syscalls arguments from the incoming type (long) to required type. #}
{% macro cast_args(args) -%}
{% for arg in args -%}
({{ arg.ctype }})arg{{ loop.index }}{% if not loop.last %}, {% endif %}
{%- endfor %}
{%- endmacro %}

{# Generates the actual return statement for a syscall. #}
{% macro syscall_do_call(syscall) -%}
  return SYSCALL_DMZ_{{ syscall.name }}({{ cast_args(syscall.args) }});
{%- endmacro %}

{# Generates the case statement for dispatching a particular syscall. #}
{% macro syscall_dispatch_case(syscall) -%}
case {{ common.syscall_constant(syscall) }}:
  {% if not syscall.can_fail %}
  kthread_current_thread()->syscall_ctx.flags &= ~SCCTX_RESTARTABLE;
  {% endif %}

  {%- if syscall.needs_32bit_conv -%}
  if (ARCH_IS_64_BIT && bin_32bit(proc_current()->user_arch)) {
  {% endif %}
    {{ syscall_do_call(syscall) }}
  {% if syscall.needs_32bit_conv %}
  } else {
    {{ syscall_do_call(syscall.native()) }}
  }
  {% endif %}
{%- endmacro %}

#include "arch/syscall/context.h"
#include "common/errno.h"
#include "common/kassert.h"
#include "common/klog.h"
#include "proc/kthread-internal.h"
#include "proc/process.h"
#include "proc/signal/signal.h"
#include "proc/user_prepare.h"
#include "syscall/syscall_dispatch.h"
#include "syscall/wrappers32.h"
#include "user/include/apos/syscalls.h"

{{ common.include_headers(SYSCALLS, 'header') }}

// Assert that all argument types are valid.
{% set arg_types = {} -%}
{%- for syscall in SYSCALLS -%}
{%- for syscall in [syscall, syscall.native()] -%}
{%- for arg in syscall.args -%}
{%- do arg_types.update([(arg.ctype, True)]) -%}
{%- endfor -%}
{%- endfor -%}
{%- endfor -%}

{% for arg_type in arg_types %}
_Static_assert(sizeof({{ arg_type }}) <= sizeof(long),
    "invalid argument type: {{ arg_type }} (sizeof({{ arg_type }}) > sizeof(long))");
{% endfor %}

// Forward declare DMZ functions.
{% for syscall in SYSCALLS %}
{{ common.syscall_decl(syscall, 'SYSCALL_DMZ_') }};
{% if syscall.needs_32bit_conv %}
{{ common.syscall_decl(syscall.native(), 'SYSCALL_DMZ_') }};
{% endif %}
{% endfor %}

static long do_syscall_dispatch(long syscall_number, long arg1, long arg2,
    long arg3, long arg4, long arg5, long arg6) {
  switch (syscall_number) {
    {% for syscall in SYSCALLS -%}
    {{ syscall_dispatch_case(syscall) | indent(4) }}

    {% endfor -%}
    default:
      proc_kill(proc_current()->id, SIGSYS);
      return -ENOTSUP;
  }
}

long syscall_dispatch(long syscall_number, long arg1, long arg2, long arg3,
    long arg4, long arg5, long arg6) {
  KASSERT_DBG(proc_current()->user_arch != BIN_NONE);
  kthread_current_thread()->syscall_ctx.flags = SCCTX_RESTARTABLE;

  klogfm(KL_SYSCALL, DEBUG, "SYSCALL %ld (%#lx, %#lx, %#lx, %#lx, %#lx, %#lx)",
         syscall_number, (unsigned long)arg1, (unsigned long)arg2,
         (unsigned long)arg3, (unsigned long)arg4, (unsigned long)arg5,
         (unsigned long)arg6);
  KASSERT_DBG(
         atomic_load_relaxed(&kthread_current_thread()->interrupt_level) == 0);

  const long result = do_syscall_dispatch(syscall_number, arg1, arg2, arg3,
      arg4, arg5, arg6);

  klogfm(KL_SYSCALL, DEBUG, " --> %ld (%#lx)\n", result, (unsigned long)result);
  return result;
}
