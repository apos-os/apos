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

{# Implementation of syscalls in user-mode, specifically for newlib. -#}
{# PY_IMPORT syscall/syscall_list.py #}
{% import "syscall/common_macros.tpl" as common %}

#include <reent.h>

{# Include the generic L1 stubs for most syscalls #}
{% include "user/syscall_stubs.tpl" %}

{# Next, generate L2 stubs (that call the L1 stubs) for all syscalls that want
  an automatically generated user-mode stub. #}
{% for syscall in SYSCALLS if 'L2' in syscall.stubs_to_generate %}
{% set syscall = syscall.native() %}
{{ syscall.return_type }} _{{ syscall.name }}_r(struct _reent* reent_ptr{% if syscall.args %}, {{ common.decl_args(syscall.args) }}{% endif %}) {
  {{ syscall.return_type }} result = _do_{{ syscall.name }}({{ syscall.args | join(', ', 'name') }});
  {% if syscall.can_fail -%}
  if (result < 0) {
    reent_ptr->_errno = -result;
    result = -1;
  }
  {% endif -%}
  return result;
}

{% endfor %}

{% include "user/newlib_syscall_stubs_manual.tpl" %}

{# Finally, generate L3 stubs (that call the L2 reentrant stubs) for syscalls
  that newlib doesn't define itself. #}
{% for syscall in SYSCALLS if 'L3' in syscall.stubs_to_generate %}
{% set syscall = syscall.native() %}
{{ common.syscall_decl(syscall, '') }} {
  return _{{ syscall.name }}_r(_REENT{% if syscall.args %}, {{ syscall.args |
      join(', ', 'name') }}{% endif %});
}

{% endfor %}
