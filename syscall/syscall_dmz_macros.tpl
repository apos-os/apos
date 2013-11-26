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

{# Helper macros for the syscall DMZ generator. #}
{% import "syscall/common_macros.tpl" as common %}

{#- Formats the arguments for use in a function call. #}
{%- macro call_args(args) -%}
{% for arg in args -%}
{% if arg.NeedsCopy() %}KERNEL_{% endif %}{{ arg.name }}{% if not loop.last %}, {% endif %}
{%- endfor %}
{%- endmacro %}

{#- Declare kernel buffers for each argument that needs copying. #}
{%- macro kernel_decls(args) -%}
{% for arg in args if arg.NeedsCopy() -%}
{{ arg.ctype }} KERNEL_{{ arg.name }} = 0x0;
{% endfor %}
{%- endmacro %}

{#- Check the validity of all buffer and string arguments. #}
{%- macro check_args(args) -%}
{% for arg in args if arg.NeedsCopy() -%}
{% if arg.IsString() -%}
const int SIZE_{{ arg.name }} = syscall_verify_string({{ arg.name }});
if (SIZE_{{ arg.name }} < 0) return SIZE_{{ arg.name }};
{% elif arg.IsBuffer() %}
const int CHECK_{{ arg.name }} = syscall_verify_buffer({{ arg.name }}, {{
    arg.size_name }}, {{ arg.IsWritable() | int }} /* is_write */,
    {{ arg.AllowNull() | int }}  /* allow_null */);
if (CHECK_{{ arg.name }} < 0) return CHECK_{{ arg.name }};
{% endif %}
{% endfor %}
{%- endmacro %}

{#- Returns the arg's size expression (size arg for buffers, or calculated size
    for strings) #}
{%- macro arg_size(arg) -%}
{% if arg.IsString() -%}SIZE_{{ arg.name }}
{%- elif arg.IsBuffer() -%}{{ arg.size_name }}{%- endif %}
{%- endmacro %}

{#- Allocate kernel buffers for each argument #}
{%- macro alloc_args(args) -%}
{% for arg in args if arg.NeedsCopy() -%}
KERNEL_{{ arg.name }} = ({{ arg.ctype }})kmalloc({{ arg_size(arg) }});
{% endfor %}
{%- endmacro %}


{%- macro free_all(args) -%}
{% for arg in args if arg.NeedsCopy() -%}
if (KERNEL_{{ arg.name }}) kfree((void*)KERNEL_{{ arg.name }});
{% endfor %}
{%- endmacro %}

{#- Create an || condition testing each allocation #}
{%- macro check_alloc_cond(args) -%}
{% for arg in args if arg.NeedsCopy() -%}
!KERNEL_{{ arg.name }}{% if not loop.last %} || {% endif %}
{%- endfor %}
{%- endmacro %}

{#- Check that allocating all the kernel buffers succeeded. #}
{%- macro check_allocs(args) -%}
{% if check_alloc_cond(args) %}
if ({{ check_alloc_cond(args) }}) {
  {{ free_all(args) | indent(2) }}
  return -ENOMEM;
}
{%- endif %}
{%- endmacro -%}

{#- Defines the DMZ function for the given syscall. #}
{% macro syscall_dmz(syscall) -%}
{{ common.syscall_decl(syscall, 'SYSCALL_DMZ_') }} {
  {{ kernel_decls(syscall.args) | indent(2) }}

  {{ check_args(syscall.args) | indent(2) }}

  {{ alloc_args(syscall.args) | indent(2) }}

  {{ check_allocs(syscall.args) | indent(2) }}

  {% for arg in syscall.args if arg.NeedsPreCopy() -%}
  kmemcpy((void*)KERNEL_{{ arg.name }}, {{ arg.name }}, {{ arg_size(arg) }});
  {% endfor %}

  const int result = {{ syscall.kernel_name }}({{ call_args(syscall.args) }});

  {% for arg in syscall.args if arg.NeedsPostCopy() -%}
  kmemcpy({{ arg.name }}, KERNEL_{{ arg.name }}, {{ arg_size(arg) }});
  {% endfor %}

  {{ free_all(syscall.args) | indent(2) }}

  return result;
}
{%- endmacro %}
