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

{# Common macros for generating syscall-related code. #}

{# Returns the constant-ified name of the syscall. #}
{% macro syscall_constant(syscall) -%}
SYS_{{ syscall.name | upper}}
{%- endmacro %}

{#- Formats the arguments for use in a function declaration. #}
{% macro decl_args(args) -%}
{% for arg in args -%}
{{ arg.ctype }} {{ arg.name }}{% if not loop.last %}, {% endif %}
{%- endfor %}
{%- endmacro %}

{#- Includes all the headers from the given attr in each syscall.  Only includes
  each unique header once. #}
{% macro include_headers(syscalls, header_attr) %}
{% for header, _ in syscalls | groupby(header_attr) if header %}
#include "{{ header }}"
{% endfor %}
{% endmacro %}
