dnl Copyright 2014 Andrew Oates.  All Rights Reserved.
dnl
dnl Licensed under the Apache License, Version 2.0 (the "License");
dnl you may not use this file except in compliance with the License.
dnl You may obtain a copy of the License at
dnl
dnl     http://www.apache.org/licenses/LICENSE-2.0
dnl
dnl Unless required by applicable law or agreed to in writing, software
dnl distributed under the License is distributed on an "AS IS" BASIS,
dnl WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
dnl See the License for the specific language governing permissions and
dnl limitations under the License.

divert(-1)
# Generates the DMZ function for each syscall.  The DMZ function is responsible
# for bounds-checking arguments and copying them into kernel memory, then
# invoking the actual syscall implementation.  It then copies any data back into
# the user-space buffers, frees the kernel buffers, and returns the result.
include(`syscall/common.m4')

define(`IDT', `')

define(`SYSCALL_DECLARG', `ARG_CTYPE(`$1') ARG_NAME(`$1')')

define(`SYSCALL_DECLARGS',
    `ifelse(`$#$1', `1', `',
            `$#', `1', `SYSCALL_DECLARG(`$1')',
            `SYSCALL_DECLARG(`$1'), SYSCALL_DECLARGS(shift($@))')')

define(`SYSCALL_FIRSTLINE',
    `IDT`'int SYSCALL_DMZ_$1(SYSCALL_DECLARGS(shift($@))) {
')

define(`SYSCALL_LASTLINE', `IDT`'}
')

# Evaluates to 1 if the argument type needs pre-copying, 0 if otherwise.
define(`ARG_NEEDS_PRE_COPY',
  `ifelse(ARG_TYPE(`$1'), `s', `1',
          ARG_TYPE(`$1'), `br', `1',
          ARG_TYPE(`$1'), `brw', `1',
          `0')')
define(`ARG_NEEDS_POST_COPY',
  `ifelse(ARG_TYPE(`$1'), `bw', `1',
          ARG_TYPE(`$1'), `brw', `1',
          `0')')
define(`ARG_NEEDS_COPY',
  `ifelse(ARG_NEEDS_PRE_COPY($@), `1', `1',
          ARG_NEEDS_POST_COPY($@), `1', `1',
          `0')')

# Evaluates to an expression equal to the size of the argument.
define(`ARG_SIZE',
  `ifelse(ARG_TYPE(`$1'), `s', `SIZE_`'ARG_NAME($1)',
          ARG_TYPE(`$1'), `br', `ARG_SIZE_NAME($1)',
          ARG_TYPE(`$1'), `bw', `ARG_SIZE_NAME($1)',
          ARG_TYPE(`$1'), `brw', `ARG_SIZE_NAME($1)',
          `errprint(invalid `ARG_SIZE' arg type)m4exit(1)')')

# Declare kernel copies of any variables that need to be copied.
define(`KERNEL_DECL', `IDT`'ARG_CTYPE(`$1') KERNEL_`'ARG_NAME(`$1') = 0x0;
')

define(`MAYBE_KERNEL_DECL',
  `ifelse(ARG_NEEDS_COPY(`$1'), `1', `KERNEL_DECL(`$1')')')

define(`KERNEL_DECLS', `arg_foreach(`MAYBE_KERNEL_DECL', $@)')

# Verify the arguments that need checking.
define(`CHECK_STRING', `dnl
IDT`'const int SIZE_`'ARG_NAME(`$1') = syscall_verify_string(ARG_NAME(`$1'));
IDT`'if (SIZE_`'ARG_NAME(`$1') < 0) return SIZE_`'ARG_NAME(`$1');
')
define(`CHECK_BUF', `dnl
IDT`'const int CHECK_`'ARG_NAME(`$1') = syscall_verify_buffer(ARG_NAME(`$1'), ARG_SIZE_NAME(`$1'), $2);
IDT`'if (CHECK_`'ARG_NAME(`$1') < 0) return CHECK_`'ARG_NAME(`$1');
')

define(`CHECK_ARG',
  `ifelse(ARG_TYPE(`$1'), `s', `CHECK_STRING($@)',
          ARG_TYPE(`$1'), `br', `CHECK_BUF($@, 0)',
          ARG_TYPE(`$1'), `bw', `CHECK_BUF($@, 1)',
          ARG_TYPE(`$1'), `brw', `CHECK_BUF($@, 1)',
          `')')
define(`CHECK_ARGS', `arg_foreach(`CHECK_ARG', $@)')

# Free all kernel copies of arguments.
define(`FREE_ARG',
  `ifelse(ARG_NEEDS_COPY($@), `1',
    `IDT`'if (KERNEL_`'ARG_NAME(`$1')) kfree((void*)KERNEL_`'ARG_NAME(`$1'));
')')
define(`FREE_ALL', `arg_foreach(`FREE_ARG', $@)')

# Allocate kernel buffers for each arg that needs copying.
define(`ALLOC_ARG',
  `ifelse(ARG_NEEDS_COPY(`$1'), `1',
    `IDT`'KERNEL_`'ARG_NAME(`$1') = (ARG_CTYPE(`$1'))kmalloc`('ARG_SIZE(`$1')`)';
')')
define(`ALLOC_ARGS', `arg_foreach(`ALLOC_ARG', $@)')

# Check that each allocation succeeded.
define(`CHECK_ALLOC_CONDITION',
  `ifelse(ARG_NEEDS_COPY(`$1'), `1', `!KERNEL_`'ARG_NAME(`$1'), ')')

define(`CHECK_ALLOCS',
  `pushdef(`_condition', `JOIN(` || ', arg_foreach(`CHECK_ALLOC_CONDITION', $@))')dnl
ifelse(_condition, `', `', `
IDT`'if (_condition) {
pushdef(`IDT', IDT`  ')dnl
FREE_ALL($@)dnl
IDT`'return -ENOMEM;
popdef(`IDT')dnl
IDT`'}')dnl
popdef(`_condition')')

# Copy the arguments that need copying before and after running the syscall.
# TODO(aoates): make sure we copy the NULL in strings as well!
define(`COPY_ARG_PRE',
  `ifelse(ARG_NEEDS_PRE_COPY(`$1'), `1',
    `IDT`'kmemcpy((void*)KERNEL_`'ARG_NAME(`$1'), `'ARG_NAME(`$1'), ARG_SIZE(`$1'));
')')
define(`COPY_ARGS_PRE', `arg_foreach(`COPY_ARG_PRE', $@)')

define(`COPY_ARG_POST',
  `ifelse(ARG_NEEDS_POST_COPY(`$1'), `1',
    `IDT`'kmemcpy(`'ARG_NAME(`$1'), KERNEL_`'ARG_NAME(`$1'), ARG_SIZE(`$1'));
')')
define(`COPY_ARGS_POST', `arg_foreach(`COPY_ARG_POST', $@)')

define(`SYSCALL_CALLARG',
  `ifelse(ARG_NEEDS_COPY(`$1'), `1', `KERNEL_`'ARG_NAME(`$1')', ARG_NAME(`$1'))')

# TODO(aoates): combine this with DECLARGS somehow
define(`SYSCALL_CALLARGS',
    `ifelse(`$#$1', `1', `',
            `$#', `1', `SYSCALL_CALLARG(`$1')',
            `SYSCALL_CALLARG(`$1'), SYSCALL_CALLARGS(shift($@))')')

define(`DEF_SYSCALL',
`pushdef(`syscall_name', `$1')dnl
pushdef(`syscall_kname', `$2')dnl
pushdef(`syscall_args', `shift(shift($@))')dnl
SYSCALL_FIRSTLINE(syscall_name, syscall_args)dnl
pushdef(`IDT', IDT`  ')dnl
dnl
KERNEL_DECLS(syscall_args)dnl

CHECK_ARGS(syscall_args)dnl

ALLOC_ARGS(syscall_args)dnl
CHECK_ALLOCS(syscall_args)dnl

COPY_ARGS_PRE(syscall_args)dnl

IDT`'const int result = syscall_kname`('SYSCALL_CALLARGS(syscall_args)`)';dnl

COPY_ARGS_POST(syscall_args)dnl

FREE_ALL(syscall_args)dnl

IDT`'return result;
popdef(`IDT')dnl
SYSCALL_LASTLINE(syscall_name, syscall_args)dnl
dnl
popdef(syscall_args)dnl
popdef(syscall_name)dnl')

divert(0)dnl
include(`syscall/syscall_dmz_preamble.m4')dnl
include(`syscall/syscall_list.m4')dnl
