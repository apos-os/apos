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
  {% if not syscall.can_fail %}
  kthread_current_thread()->syscall_ctx.flags &= ~SCCTX_RESTARTABLE;
  {% endif %}
  return SYSCALL_DMZ_{{ syscall.name }}({{ cast_args(syscall.args) }});
{%- endmacro %}

#include "arch/syscall/context.h"
#include "common/errno.h"
#include "common/klog.h"
#include "proc/process.h"
#include "proc/signal/signal.h"
#include "proc/user_prepare.h"
#include "user/include/apos/syscalls.h"

{{ common.include_headers(SYSCALLS, 'header') }}

// Assert that all argument types are valid.
{% set arg_types = {} -%}
{%- for syscall in SYSCALLS -%}
{%- for arg in syscall.args -%}
{%- do arg_types.update([(arg.ctype, True)]) -%}
{%- endfor -%}
{%- endfor -%}

{% for arg_type in arg_types %}
_Static_assert(sizeof({{ arg_type }}) <= sizeof(long),
    "invalid argument type: {{ arg_type }} (sizeof({{ arg_type }}) != sizeof(long))");
{% endfor %}

// Forward declare DMZ functions.
{% for syscall in SYSCALLS %}
{{ common.syscall_decl(syscall, 'SYSCALL_DMZ_') }};
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

static user_context_t syscall_extract_context_tramp(void* arg) {
  return syscall_extract_context(*(long*)arg);
}

long syscall_dispatch(long syscall_number, long arg1, long arg2, long arg3,
    long arg4, long arg5, long arg6) {
  kthread_current_thread()->syscall_ctx.flags = SCCTX_RESTARTABLE;

  klogfm(KL_SYSCALL, DEBUG, "SYSCALL %ld (%#lx, %#lx, %#lx, %#lx, %#lx, %#lx)",
         syscall_number, (unsigned long)arg1, (unsigned long)arg2,
         (unsigned long)arg3, (unsigned long)arg4, (unsigned long)arg5,
         (unsigned long)arg6);

  const long result = do_syscall_dispatch(syscall_number, arg1, arg2, arg3,
      arg4, arg5, arg6);

  klogfm(KL_SYSCALL, DEBUG, " --> %ld (%#lx)\n", result, (unsigned long)result);

  proc_prep_user_return(&syscall_extract_context_tramp, (void*)&result,
                        &kthread_current_thread()->syscall_ctx);

  // Don't do anything here!  After we call proc_prep_user_return(), we may
  // never return.
  return result;
}
