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
#
# The buffer types can be followed by a '?', which means that the argument is
# allowed to be NULL.

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

    if self.arg_type[-1] == '?':
      self.arg_type = self.arg_type[:-1]
      assert self.arg_type.startswith('b')
      self.allow_null = True
    else:
      self.allow_null = False

    assert self.arg_type in ['u', 's', 'br', 'bw', 'brw']

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

  def AllowNull(self):
    return self.allow_null


class SyscallDef(object):
  def __init__(self, name, number, kernel_name,
      header, user_header, return_type, args,
      generate_user_stub=True):
    assert len(args) <= MAX_ARGS
    self.name = name
    self.number = number
    self.kernel_name = kernel_name
    self.header = header
    self.user_header = user_header
    self.return_type = return_type
    self.args = [SyscallArg(x) for x in args]
    self.generate_user_stub = generate_user_stub


def AddSyscall(*args, **kwargs):
  syscall = SyscallDef(*args, **kwargs)
  assert syscall.name not in [s.name for s in SYSCALLS]
  assert syscall.number not in [s.number for s in SYSCALLS]
  SYSCALLS.append(syscall)


AddSyscall('syscall_test', 0, 'do_syscall_test',
    'syscall/test.h', 'user/test.h',
    'long', [
    'long:arg1:u',
    'long:arg2:u',
    'long:arg3:u',
    'long:arg4:u',
    'long:arg5:u',
    'long:arg6:u'])

AddSyscall('open', 1, 'vfs_open', 'vfs/vfs.h', 'user/fs.h',
    'int', [
    'const char*:path:s',
    'uint32_t:flags:u'])

AddSyscall('close', 2, 'vfs_close', 'vfs/vfs.h', 'user/fs.h',
    'int', [
    'int:fd:u'])

AddSyscall('mkdir', 3, 'vfs_mkdir', 'vfs/vfs.h', 'user/fs.h',
    'int', [
    'const char*:path:s'])

AddSyscall('mknod', 4, 'vfs_mknod_wrapper', 'syscall/wrappers.h', 'user/fs.h',
    'int', [
    'const char*:path:s',
    'uint32_t:mode:u',
    'int:dev_major:u',
    'int:dev_minor:u'],
    generate_user_stub=False)

AddSyscall('rmdir', 5, 'vfs_rmdir', 'vfs/vfs.h', 'user/fs.h',
    'int', [
    'const char*:path:s'])

AddSyscall('unlink', 6, 'vfs_unlink', 'vfs/vfs.h', 'user/fs.h',
    'int', [
    'const char*:path:s'])

AddSyscall('read', 7, 'vfs_read', 'vfs/vfs.h', 'user/fs.h',
    'int', [
    'int:fd:u',
    'void*:buf:bw:count',
    'int:count:u'])

AddSyscall('write', 8, 'vfs_write', 'vfs/vfs.h', 'user/fs.h',
    'int', [
    'int:fd:u',
    'const void*:buf:br:count',
    'int:count:u'])

AddSyscall('seek', 9, 'vfs_seek', 'vfs/vfs.h', 'user/fs.h',
    'int', [
    'int:fd:u',
    'int:offset:u',
    'int:whence:u'])

AddSyscall('getdents', 10, 'vfs_getdents', 'vfs/vfs.h', 'user/fs.h',
    'int', [
    'int:fd:u',
    'dirent_t*:buf:bw:count',
    'int:count:u'])

AddSyscall('getcwd', 11, 'vfs_getcwd', 'vfs/vfs.h', 'user/fs.h',
    'int', [
    'char*:path_out:bw:size',
    'int:size:u'])

AddSyscall('chdir', 12, 'vfs_chdir', 'vfs/vfs.h', 'user/fs.h',
    'int', [
    'const char*:path:s'])

AddSyscall('fork', 13, 'proc_fork_syscall', 'syscall/fork.h', 'user/process.h',
    'pid_t', [])

AddSyscall('exit', 14, 'proc_exit_wrapper', 'syscall/wrappers.h',
    'user/process.h',
    'int', [
    'int:status:u'],
    generate_user_stub=False)

# The execve wrapper manually checks its arguments so that it can clean up the
# allocated kernel copies properly (since on success, do_execve will never
# return).
AddSyscall('execve', 15, 'execve_wrapper', 'syscall/wrappers.h',
    'user/process.h',
    'int', [
    'const char*:path:u', # Manually checked by the wrapper.
    'char* const*:argv:u',  # Manually checked by the wrapper.
    'char* const*:envp:u',  # Manually checked by the wrapper.
    ])

AddSyscall('getpid', 16, 'getpid_wrapper', 'syscall/wrappers.h',
    'user/process.h',
    'pid_t', []);

AddSyscall('getppid', 17, 'getppid_wrapper', 'syscall/wrappers.h',
    'user/process.h',
    'pid_t', []);

AddSyscall('isatty', 18, 'vfs_isatty', 'vfs/vfs.h', 'user/fs.h',
    'int', [
    'int:fd:u'])

AddSyscall('kill', 19, 'proc_kill', 'proc/signal/signal.h', 'user/signal.h',
    'int', [
    'pid_t:pid:u',
    'int:sig:u'])

AddSyscall('sigaction', 20, 'proc_sigaction', 'proc/signal/signal.h',
    'user/signal.h',
    'int', [
    'int:signum:u',
    'const struct sigaction*:act:br?:sizeof(struct sigaction)',
    'struct sigaction*:oldact:bw?:sizeof(struct sigaction)'])

AddSyscall('sigreturn', 21, 'proc_sigreturn', 'proc/signal/signal.h',
    'user/signal.h',
    'int', [
    'const sigset_t*:old_mask:br:sizeof(sigset_t)',
    'const user_context_t*:context:br:sizeof(user_context_t)'])

AddSyscall('alarm', 22, 'proc_alarm', 'proc/alarm.h',
    'user/signal.h',
    'unsigned int', [
    'unsigned int:seconds:u'])

AddSyscall('setuid', 23, 'setuid', 'proc/user.h', 'user/process.h',
    'int', ['uid_t:uid:u'])

AddSyscall('setgid', 24, 'setgid', 'proc/user.h', 'user/process.h',
    'int', ['gid_t:gid:u'])

AddSyscall('getuid', 25, 'getuid', 'proc/user.h', 'user/process.h',
    'uid_t', [])

AddSyscall('getgid', 26, 'getgid', 'proc/user.h', 'user/process.h',
    'gid_t', [])

AddSyscall('seteuid', 27, 'seteuid', 'proc/user.h', 'user/process.h',
    'int', ['uid_t:uid:u'])

AddSyscall('setegid', 28, 'setegid', 'proc/user.h', 'user/process.h',
    'int', ['gid_t:gid:u'])

AddSyscall('geteuid', 29, 'geteuid', 'proc/user.h', 'user/process.h',
    'uid_t', [])

AddSyscall('getegid', 30, 'getegid', 'proc/user.h', 'user/process.h',
    'gid_t', [])

AddSyscall('setreuid', 31, 'setreuid', 'proc/user.h', 'user/process.h',
    'int', ['uid_t:ruid:u', 'uid_t:euid:u'])

AddSyscall('setregid', 32, 'setregid', 'proc/user.h', 'user/process.h',
    'int', ['gid_t:rgid:u', 'gid_t:egid:u'])

AddSyscall('getpgid', 33, 'getpgid', 'proc/group.h', 'user/process.h',
    'pid_t', ['pid_t:pid:u'])

AddSyscall('setpgid', 34, 'setpgid', 'proc/group.h', 'user/process.h',
    'int', ['pid_t:pid:u', 'pid_t:pgid:u'])
