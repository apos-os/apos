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
{#- This is sort of a hack to get around funny business with signed/unsigned
    conversions.  TODO(aoates): do this checking in a more principled way. #}
{% if arg.AllowNull() %} if ({{ arg.name }}) { {% endif %}
if ((size_t)({{ arg.size_name }}) > DMZ_MAX_BUFSIZE) return -EINVAL;
{% if arg.AllowNull() %} } {% endif %}
{% endif %}
{% endfor %}
{%- endmacro %}

{#- Returns the arg's size expression (size arg for buffers, or calculated size
    for strings) #}
{%- macro arg_size(arg) -%}
{% if arg.IsString() -%}SIZE_{{ arg.name }}
{%- elif arg.IsBuffer() -%}{{ arg.size_name }}{%- endif %}
{%- endmacro %}

{#- Allocate a kernel buffer for the given argument if it's non-NULL #}
{%- macro alloc_arg(arg) -%}
KERNEL_{{ arg.name }} = {% if arg.AllowNull() %}!{{ arg.name }} ? 0x0 : {% endif -%}
({{ arg.ctype }})kmalloc({{ arg_size(arg) }});
{%- endmacro %}

{#- Allocate kernel buffers for each argument #}
{%- macro alloc_args(args) -%}
{% for arg in args if arg.NeedsCopy() -%}
{{ alloc_arg(arg) }}
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
{% if arg.AllowNull() -%}
  ({{ arg.name }} && !KERNEL_{{ arg.name }})
{%- else -%}
  !KERNEL_{{ arg.name }}
{%- endif -%}
{% if not loop.last %} || {% endif %}
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
{#- Forward-declare the kernel function name with the same types --- this will
catch if the types don't match (but are convertible between each other). #}
{%- if not syscall.mismatched_kernel_types %}
{{ syscall.return_type }} {{ syscall.kernel_name }}({{ common.decl_args(syscall.args) }});
{%- endif -%}

{{ common.syscall_decl(syscall, 'SYSCALL_DMZ_') }} {
  {{ kernel_decls(syscall.args) | indent(2) }}

  {{ check_args(syscall.args) | indent(2) }}

  {{ alloc_args(syscall.args) | indent(2) }}

  {{ check_allocs(syscall.args) | indent(2) }}

  int result;
  {% for arg in syscall.args if arg.NeedsPreCopy() -%}
  {# Only check if the argument is NULL if it's allowed to be null; if not
     allowed to be NULL, and the user passed NULL, then syscall_copy_from_user()
     will catch that and generate an appropriate signal/error. #}
  {% if arg.AllowNull() %} if ({{ arg.name }}) { {% endif %}
    result = syscall_copy_from_user({{ arg.name }}, (void*)KERNEL_{{ arg.name }}, {{ arg_size(arg) }});
    if (result) goto cleanup;
  {% if arg.AllowNull() %} } {% endif %}
  {% endfor %}

  result = {{ syscall.kernel_name }}({{ call_args(syscall.args) }});

  // TODO(aoates): this should only copy the written bytes, not the full kernel
  // buffer (e.g. in a read() syscall).
  {% for arg in syscall.args if arg.NeedsPostCopy() -%}
  {% if arg.AllowNull() %} if ({{ arg.name }}) { {% endif %} {# As above. #}
    int copy_result = syscall_copy_to_user(KERNEL_{{ arg.name }}, {{ arg.name }}, {{ arg_size(arg) }});
    if (copy_result) {
      result = copy_result;
      goto cleanup;
    }
  {% if arg.AllowNull() %} } {% endif %}
  {% endfor %}

  goto cleanup;  // Make the compiler happy if cleanup is otherwise unused.

cleanup:
  {{ free_all(syscall.args) | indent(2) }}

  return result;
}
{%- endmacro %}
