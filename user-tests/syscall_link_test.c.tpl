// Copyright 2026 Andrew Oates.  All Rights Reserved.
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

{# PY_IMPORT syscall/syscall_list.py -#}
{% import "syscall/common_macros.tpl" as common %}

#include <apos/syscall_decls.h>
#include <sys/time.h>  // For utimes, gettimeofday
#include <unistd.h>  // For sbrk

// This file simply calls every syscall we know must be defined in the standard
// userspace environment.  This verifies that all functions are linked properly
// into libc, without having to test compiling multiple different userspace
// binaries that use different subsets.

// First, the syscalls defined built-in by APOS.
static void direct_syscalls(void) {
  {% for syscall in SYSCALLS if syscall.stubs_to_generate %}
  {% set syscall = syscall.native() %}
  {{ syscall.name }}(
    {% for arg in syscall.args -%}
      {% if '*' in arg.ctype %} NULL {% else %} 0 {% endif %}
        {%- if not loop.last %}, {% endif %}
    {%- endfor %}
      );
  {% endfor %}
}

// Syscalls implemented in userspace, or libc functions.
static void userspace_functions(void) {
  utimes(0, NULL);
  sbrk(0);
  gettimeofday(NULL, NULL);
}

int main(void) {
  direct_syscalls();
  userspace_functions();
}
