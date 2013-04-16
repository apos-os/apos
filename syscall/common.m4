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

# Common macros for use by the syscall M4 files.
# TODO(aoates): clean these up.
define(`ARG_FIELD',
  `ifelse(`$1'index(`$2', `:'), `1-1', `$2',
          `$1', `1', `substr(`$2', `0', index(`$2', `:'))',
          `ARG_FIELD(decr(`$1'), substr(`$2', incr(index(`$2', `:'))))')')

define(`ARG_CTYPE', `ARG_FIELD(1, `$1')')
define(`ARG_NAME', `ARG_FIELD(2, `$1')')
define(`ARG_TYPE', `ARG_FIELD(3, `$1')')
define(`ARG_SIZE_NAME', `ARG_FIELD(4, `$1')')

# Usage: JOIN(delimeter, ...)
define(`JOIN',
  `ifelse(`$#', `2', `$2',
          `$2', `', `$0(`$1', shift(shift($@)))',
          `$2`'_$0(`$1', shift(shift($@)))')')

define(`_JOIN',
  `ifelse(`$#$2', `2', `',
          `$2', `', `$0(`$1', shift(shift($@)))',
          `$1`'$2`'$0(`$1', shift(shift($@)))')')

define(`ARG1', `$1')

# Expand the given macro for each argument.
define(`arg_foreach',
  `ifelse(`$#', `1', `',
          `$#', `2', `$1(ARG1(shift($@)))',
          `$1(ARG1(shift($@)))`'arg_foreach(`$1', shift(shift($@)))')')
