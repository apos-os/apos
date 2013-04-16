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

include(`syscall/common.m4')

define(`IDT', `')

define(`SYSCALL_CONSTANT',
    `SYS_`'translit(`$1', `a-z', `A-Z')')

define(`CAST_ARG',
    `define(`_arg_counter', incr(_arg_counter))dnl
ifelse(`$1', `', `', ``'(ARG_CTYPE(`$1'))arg`'_arg_counter, ')')

define(`CAST_ARGS',
  `pushdef(`_arg_counter', `0')dnl
JOIN(`, ', arg_foreach(`CAST_ARG', $@))')dnl
popdef(`_arg_counter')'

define(`SYSCALL_DISPATCH_CASE', `dnl
IDT`'case SYSCALL_CONSTANT(`$1'):
IDT`'  return SYSCALL_DMZ_`'$1`'(CAST_ARGS(shift(shift($@))));')

define(`DECL_ARG', `ARG_CTYPE(`$1') ARG_NAME(`$1'), ')
define(`SYSCALL_FORWARD_DECL', `dnl
IDT`'long SYSCALL_DMZ_`'$1`'(JOIN(`, ', arg_foreach(`DECL_ARG', shift(shift($@)))));')

divert(0)dnl
include(`syscall/syscall_dispatch_preamble.m4')dnl

// Forward declare DMZ functions.
define(`DEF_SYSCALL', defn(`SYSCALL_FORWARD_DECL'))dnl
include(`syscall/syscall_list.m4')dnl

IDT`'long syscall_dispatch(long syscall_number, long arg1, long arg2, long arg3,
  long arg4, long arg5, long arg6) {
pushdef(`IDT', IDT`  ')dnl
IDT`'switch (syscall_number) {
pushdef(`IDT', IDT`  ')dnl
define(`DEF_SYSCALL', defn(`SYSCALL_DISPATCH_CASE'))dnl
include(`syscall/syscall_list.m4')dnl

IDT`'default:
IDT`'  return -ENOTSUP;
popdef(`IDT')dnl
IDT`'}
popdef(`IDT')dnl
}
