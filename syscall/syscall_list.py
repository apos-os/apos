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

# List of syscalls the kernel can handle.  Each syscall has a name (used for
# the user-space function and various constants), a kernel function (that
# implements the syscall), and a list of arguments.
#
# Argument format:
#   <C type>:<name>:<m4 type>:<len arg, if needed>
#
# For example,
#   int:fd:u:xxx
#
# is an unchecked int arg named 'fd'
#
#   void*:buf:bw:count
#
# is a checked, writable, void* buffer arg named 'buf', where the argument
# 'count' is the length of the buffer.
#
# Argument types:
#   u --> Unchecked.
#   s --> NULL-terminated string (checked)
#   br --> read-only buffer (checked)
#   bw --> write-only buffer (checked)
#   brw --> read/write buffer (checked)

# Maximum number of arguments.
MAX_ARGS = 6

# Global list of syscalls.
SYSCALLS = []

class SyscallArg(object):
  def __init__(self, desc):
    split = desc.split(':')
    self.ctype = split[0]
    self.name = split[1]
    self.arg_type = split[2]
    if len(split) == 4:
      self.size_name = split[3]

  def NeedsPreCopy(self):
    return (self.arg_type == 's' or self.arg_type == 'br' or
        self.arg_type == 'brw')

  def NeedsPostCopy(self):
    return self.arg_type == 'bw' or self.arg_type == 'brw'

  def NeedsCopy(self):
    return self.NeedsPreCopy() or self.NeedsPostCopy()

  def IsString(self):
    return self.arg_type == 's'

  def IsBuffer(self):
    return (self.arg_type == 'br' or self.arg_type == 'bw' or
        self.arg_type == 'brw')

  def IsWritable(self):
    return self.arg_type == 'bw' or self.arg_type == 'brw'


class SyscallDef(object):
  def __init__(self, name, kernel_name, header, args):
    assert len(args) <= MAX_ARGS
    self.name = name
    self.kernel_name = kernel_name
    self.header = header
    self.args = [SyscallArg(x) for x in args]


def AddSyscall(*args):
  SYSCALLS.append(SyscallDef(*args))


AddSyscall('syscall_test', 'do_syscall_test', 'syscall/test.h', [
    'long:arg1:u',
    'long:arg2:u',
    'long:arg3:u',
    'long:arg4:u',
    'long:arg5:u',
    'long:arg6:u'])

AddSyscall('open', 'vfs_open', 'vfs/vfs.h', [
    'const char*:path:s',
    'int:mode:u'])

AddSyscall('read', 'vfs_read', 'vfs/vfs.h', [
    'int:fd:u',
    'void*:buf:bw:count',
    'int:count:u'])

AddSyscall('write', 'vfs_write', 'vfs/vfs.h', [
    'int:fd:u',
    'const void*:buf:br:count',
    'int:count:u'])
