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
#
# If needs_32bit_conv is set on the syscall, this indicates that the syscall
# depends on type sizes that differ between 32 and 64-bit modes (such as
# 'long'), generally by pointing to a struct containing the type(s).
#
# If set, different copies of the syscall kernel handlers will be generated in
# 32 and 64 bit kernels.  For 64-bit kernels, if the 32-bit version of syscall
# is invoked (e.g. from a 32-bit program), a special wrapper will be run (see
# wrappers32.{h,c}) that converts to/from the native 64-bit versions of the
# arguments.

import copy

# Maximum number of arguments.
MAX_ARGS = 6

# Global list of syscalls.
SYSCALLS = []

class SyscallArg(object):
  def __init__(self, desc, needs_32bit_conv):
    self.needs_32bit_conv = needs_32bit_conv
    split = desc.split(':')
    self._ctype = split[0]
    self.name = split[1]
    self.arg_type = split[2]
    if len(split) == 4:
      self._size_name = split[3]

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

  @property
  def ctype(self):
    return self._ctype % {'s32': '_32' if self.needs_32bit_conv else ''}

  @property
  def size_name(self):
    return self._size_name  % {'s32': '_32' if self.needs_32bit_conv else ''}

class SyscallDef(object):
  def __init__(self, name, number, kernel_name,
      header, user_header, return_type, args,
      stubs_to_generate=None, can_fail=True,
      needs_32bit_conv=False, newlib_defined=False,
      mismatched_kernel_types=False):
    assert len(args) <= MAX_ARGS
    if stubs_to_generate is None:
      # syscalls defined in newlib will have their own 'L3' stubs already.
      if newlib_defined:
        stubs_to_generate = ['L1', 'L2']
      else:
        stubs_to_generate = ['L1', 'L2', 'L3']

    self.needs_32bit_conv = needs_32bit_conv
    self._name = name
    self.number = number
    self._kernel_name = kernel_name
    self.header = header
    self.user_header = user_header
    self.return_type = return_type
    self.args = [SyscallArg(x, self.needs_32bit_conv) for x in args]
    self.stubs_to_generate = stubs_to_generate
    # Determines if we do errno conversion.
    self.can_fail = can_fail
    # Dictates whether the kernel syscall function must have the same type
    # exactly as the declared syscall here.
    self.mismatched_kernel_types = mismatched_kernel_types

  @property
  def name(self):
    return self._name + ('_32' if self.needs_32bit_conv else '')

  @property
  def kernel_name(self):
    return self._kernel_name + ('_32' if self.needs_32bit_conv else '')

  def native(self):
    """Returns a version of the syscall without any 32/64 bit conversions.

    Use if you need to generate something seen by userspace (which will always
    use the 'native' types and syscall names).
    """
    native = copy.deepcopy(self)
    native.needs_32bit_conv = False
    for arg in native.args:
      arg.needs_32bit_conv = False
    return native


def AddSyscall(*args, **kwargs):
  syscall = SyscallDef(*args, **kwargs)
  assert syscall.name not in [s.name for s in SYSCALLS]
  assert syscall.number not in [s.number for s in SYSCALLS]
  SYSCALLS.append(syscall)


# Leave syscall 0 intentionally unallocated to catch bugs.
AddSyscall('syscall_test', 100, 'do_syscall_test',
    'syscall/test.h', '<apos/test.h>',
    'long', [
    'long:arg1:u',
    'long:arg2:u',
    'long:arg3:u',
    'long:arg4:u',
    'long:arg5:u',
    'long:arg6:u'])

AddSyscall('open', 1, 'vfs_open', 'vfs/vfs.h', '<fcntl.h>',
    'int', [
    'const char*:path:s',
    'int:flags:u',
    'apos_mode_t:mode:u'],
    newlib_defined=True,
    mismatched_kernel_types=True)  # vfs_open() uses varargs

AddSyscall('close', 2, 'vfs_close', 'vfs/vfs.h', '<unistd.h>',
    'int', [
    'int:fd:u'],
    newlib_defined=True)

AddSyscall('dup', 45, 'vfs_dup', 'vfs/vfs.h', '<unistd.h>',
    'int', ['int:fd:u'])

AddSyscall('dup2', 46, 'vfs_dup2', 'vfs/vfs.h', '<unistd.h>',
    'int', ['int:fd1:u', 'int:fd2:u'])

AddSyscall('mkdir', 3, 'vfs_mkdir', 'vfs/vfs.h', '<sys/stat.h>',
    'int', [
    'const char*:path:s',
    'apos_mode_t:mode:u',
    ])

AddSyscall('mknod', 4, 'vfs_mknod', 'vfs/vfs.h',
    '<sys/stat.h>',
    'int', [
    'const char*:path:s',
    'apos_mode_t:mode:u',
    'apos_dev_t:dev:u'])

AddSyscall('rmdir', 5, 'vfs_rmdir', 'vfs/vfs.h', '<unistd.h>',
    'int', [
    'const char*:path:s'])

AddSyscall('link', 72, 'vfs_link', 'vfs/vfs.h', '<unistd.h>',
    'int', ['const char*:path1:s', 'const char*:path2:s'],
    newlib_defined=True)

AddSyscall('rename', 73, 'vfs_rename', 'vfs/vfs.h', '<stdio.h>',
    'int', ['const char*:path1:s', 'const char*:path2:s'],
    newlib_defined=True)

AddSyscall('unlink', 6, 'vfs_unlink', 'vfs/vfs.h', '<unistd.h>',
    'int', [
    'const char*:path:s'],
    newlib_defined=True)

AddSyscall('read', 7, 'vfs_read', 'vfs/vfs.h', '<unistd.h>',
    'ssize_t', [
    'int:fd:u',
    'void*:buf:bw:count',
    'size_t:count:u'],
    newlib_defined=True)

AddSyscall('write', 8, 'vfs_write', 'vfs/vfs.h', '<unistd.h>',
    'ssize_t', [
    'int:fd:u',
    'const void*:buf:br:count',
    'size_t:count:u'],
    newlib_defined=True)

AddSyscall('getdents', 10, 'vfs_getdents', 'vfs/vfs.h', '<dirent.h>',
    'int', [
    'int:fd:u',
    'kdirent%(s32)s_t*:buf:bw:count',
    'int:count:u'],
    needs_32bit_conv=True)

AddSyscall('getcwd', 11, 'vfs_getcwd', 'vfs/vfs.h', '<unistd.h>',
    'int', [
    'char*:path_out:bw:size',
    'size_t:size:u'],
    stubs_to_generate=['L1'])

AddSyscall('stat', 35, 'vfs_stat', 'vfs/vfs.h', '<sys/stat.h>',
    'int', [
    'const char*:path:s',
    'apos_stat%(s32)s_t*:stat:bw:sizeof(apos_stat%(s32)s_t)'],
    needs_32bit_conv=True, newlib_defined=True)

AddSyscall('lstat', 36, 'vfs_lstat', 'vfs/vfs.h', '<sys/stat.h>',
    'int', [
    'const char*:path:s',
    'apos_stat%(s32)s_t*:stat:bw:sizeof(apos_stat%(s32)s_t)'],
    needs_32bit_conv=True)

AddSyscall('fstat', 37, 'vfs_fstat', 'vfs/vfs.h', '<sys/stat.h>',
    'int', [
    'int:fd:u',
    'apos_stat%(s32)s_t*:stat:bw:sizeof(apos_stat%(s32)s_t)'],
    needs_32bit_conv=True, newlib_defined=True)

AddSyscall('lseek', 38, 'vfs_seek', 'vfs/vfs.h', '<unistd.h>',
    'apos_off_t', [
    'int:fd:u',
    'apos_off_t:offset:u',
    'int:whence:u'],
    newlib_defined=True)

AddSyscall('chdir', 12, 'vfs_chdir', 'vfs/vfs.h', '<unistd.h>',
    'int', [
    'const char*:path:s'])

AddSyscall('access', 47, 'vfs_access', 'vfs/vfs.h', '<unistd.h>',
    'int', ['const char*:path:s', 'int:amode:u'])

AddSyscall('chown', 48, 'vfs_chown', 'vfs/vfs.h', '<unistd.h>',
    'int', ['const char*:path:s', 'apos_uid_t:owner:u', 'apos_gid_t:group:u'])

AddSyscall('fchown', 49, 'vfs_fchown', 'vfs/vfs.h', '<unistd.h>',
    'int', ['int:fd:u', 'apos_uid_t:owner:u', 'apos_gid_t:group:u'])

AddSyscall('lchown', 50, 'vfs_lchown', 'vfs/vfs.h', '<unistd.h>',
    'int', ['const char*:path:s', 'apos_uid_t:owner:u', 'apos_gid_t:group:u'])

AddSyscall('chmod', 70, 'vfs_chmod', 'vfs/vfs.h', '<sys/stat.h>',
    'int', ['const char*:path:s', 'apos_mode_t:mode:u'])

AddSyscall('fchmod', 71, 'vfs_fchmod', 'vfs/vfs.h', '<sys/stat.h>',
    'int', ['int:fd:u', 'apos_mode_t:mode:u'])

AddSyscall('fork', 13, 'proc_fork_syscall', 'syscall/fork.h', '<unistd.h>',
    'apos_pid_t', [], newlib_defined=True)

AddSyscall('vfork', 74, 'proc_fork_syscall', 'syscall/fork.h', '<unistd.h>',
    'apos_pid_t', [])

AddSyscall('exit', 14, 'proc_exit_wrapper', 'syscall/wrappers.h',
    '',
    'int', [
    'int:status:u'],
    stubs_to_generate=['L1'],
    can_fail=False)

AddSyscall('wait', 41, 'proc_wait', 'proc/wait.h', '<sys/wait.h>',
    'apos_pid_t', ['int*:exit_status:bw?:sizeof(int)'],
    newlib_defined=True)

AddSyscall('waitpid', 62, 'proc_waitpid', 'proc/wait.h', '<sys/wait.h>',
    'apos_pid_t', ['apos_pid_t:child:u', 'int*:exit_status:bw?:sizeof(int)',
      'int:options:u'])

# The execve wrapper manually checks its arguments so that it can clean up the
# allocated kernel copies properly (since on success, do_execve will never
# return).
AddSyscall('execve', 15, 'execve_wrapper', 'syscall/execve_wrapper.h',
    '<unistd.h>',
    'int', [
    'const char*:path:u', # Manually checked by the wrapper.
    'char* const*:argv:u',  # Manually checked by the wrapper.
    'char* const*:envp:u',  # Manually checked by the wrapper.
    ],
    needs_32bit_conv=True, newlib_defined=True)

AddSyscall('getpid', 16, 'getpid_wrapper', 'syscall/wrappers.h',
    '<unistd.h>',
    'apos_pid_t', [], can_fail=False,
    newlib_defined=True)

AddSyscall('getppid', 17, 'getppid_wrapper', 'syscall/wrappers.h',
    '<unistd.h>',
    'apos_pid_t', [], can_fail=False)

AddSyscall('isatty', 18, 'vfs_isatty', 'vfs/vfs.h', '<unistd.h>',
    'int', [
    'int:fd:u'],
    newlib_defined=True)

AddSyscall('kill', 19, 'proc_kill', 'proc/signal/signal.h', '<signal.h>',
    'int', [
    'apos_pid_t:pid:u',
    'int:sig:u'],
    newlib_defined=True)

AddSyscall('sigaction', 20, 'proc_sigaction', 'proc/signal/signal.h',
    '<signal.h>',
    'int', [
    'int:signum:u',
    'const struct ksigaction%(s32)s*:act:br?:sizeof(struct ksigaction%(s32)s)',
    'struct ksigaction%(s32)s*:oldact:bw?:sizeof(struct ksigaction%(s32)s)'],
    needs_32bit_conv=True)

AddSyscall('sigprocmask', 52, 'proc_sigprocmask', 'proc/signal/signal.h',
    '<signal.h>',
    'int', ['int:how:u', 'const ksigset_t*:set:br?:sizeof(ksigset_t)',
            'ksigset_t*:oset:bw?:sizeof(ksigset_t)'])

AddSyscall('sigpending', 53, 'proc_sigpending', 'proc/signal/signal.h',
    '<signal.h>',
    'int', ['ksigset_t*:oset:bw:sizeof(ksigset_t)'])

AddSyscall('sigsuspend', 61, 'proc_sigsuspend', 'proc/signal/signal.h',
    '<signal.h>',
    'int', ['const ksigset_t*:sigmask:br:sizeof(ksigset_t)'])

AddSyscall('sigreturn', 21, 'proc_sigreturn', 'proc/signal/signal.h',
    '',
    'int', [
    'const ksigset_t*:old_mask:br:sizeof(ksigset_t)',
    'const user_context_t*:context:br:sizeof(user_context_t)',
    'const syscall_context_t*:syscall_context:br?:sizeof(syscall_context_t)'],
    stubs_to_generate=[])

AddSyscall('alarm_ms', 22, 'proc_alarm_ms', 'proc/alarm.h',
    '<unistd.h>',
    'unsigned int', [
    'unsigned int:seconds:u'],
    can_fail=False)

AddSyscall('setuid', 23, 'setuid', 'proc/user.h', '<unistd.h>',
    'int', ['apos_uid_t:uid:u'])

AddSyscall('setgid', 24, 'setgid', 'proc/user.h', '<unistd.h>',
    'int', ['apos_gid_t:gid:u'])

AddSyscall('getuid', 25, 'getuid', 'proc/user.h', '<unistd.h>',
    'apos_uid_t', [], can_fail=False)

AddSyscall('getgid', 26, 'getgid', 'proc/user.h', '<unistd.h>',
    'apos_gid_t', [], can_fail=False)

AddSyscall('seteuid', 27, 'seteuid', 'proc/user.h', '<unistd.h>',
    'int', ['apos_uid_t:uid:u'])

AddSyscall('setegid', 28, 'setegid', 'proc/user.h', '<unistd.h>',
    'int', ['apos_gid_t:gid:u'])

AddSyscall('geteuid', 29, 'geteuid', 'proc/user.h', '<unistd.h>',
    'apos_uid_t', [], can_fail=False)

AddSyscall('getegid', 30, 'getegid', 'proc/user.h', '<unistd.h>',
    'apos_gid_t', [], can_fail=False)

AddSyscall('setreuid', 31, 'setreuid', 'proc/user.h', '<unistd.h>',
    'int', ['apos_uid_t:ruid:u', 'apos_uid_t:euid:u'])

AddSyscall('setregid', 32, 'setregid', 'proc/user.h', '<unistd.h>',
    'int', ['apos_gid_t:rgid:u', 'apos_gid_t:egid:u'])

AddSyscall('getpgid', 33, 'getpgid', 'proc/group.h', '<unistd.h>',
    'apos_pid_t', ['apos_pid_t:pid:u'])

AddSyscall('setpgid', 34, 'setpgid', 'proc/group.h', '<unistd.h>',
    'int', ['apos_pid_t:pid:u', 'apos_pid_t:pgid:u'])

AddSyscall('mmap', 39, 'mmap_wrapper', 'syscall/wrappers.h', '<sys/mman.h>',
        'int', ['void*:addr_inout:brw:sizeof(void*)', 'size_t:length:u',
                 'int:prot:u', 'int:flags:u', 'int:fd:u', 'apos_off_t:offset:u'],
        stubs_to_generate=['L1'], needs_32bit_conv=True)

AddSyscall('munmap', 40, 'do_munmap', 'memory/mmap.h', '<sys/mman.h>',
        'int', ['void*:addr:u', 'size_t:length:u'])

AddSyscall('symlink', 42, 'vfs_symlink', 'vfs/vfs.h', '<unistd.h>',
    'int', ['const char*:path1:s', 'const char*:path2:s'])

AddSyscall('readlink', 43, 'vfs_readlink', 'vfs/vfs.h', '<unistd.h>',
    'int', ['const char*:path:s', 'char*:buf:bw:bufsize', 'size_t:bufsize:u'])

AddSyscall('sleep_ms', 44, 'ksleep', 'proc/sleep.h', '<apos/sleep.h>',
    'int', ['int:seconds:u'])

AddSyscall('apos_get_time', 51, 'apos_get_time', 'common/time.h',
    '<apos/syscall_decls.h>', 'int',
    ['struct apos_tm*:t:bw:sizeof(struct apos_tm)'])

AddSyscall('pipe', 54, 'vfs_pipe', 'vfs/pipe.h', '<unistd.h>',
    'int', ['int*:fildes:bw:sizeof(int[2])'],
     stubs_to_generate=['L1', 'L2'],
     mismatched_kernel_types=True)

AddSyscall('umask', 55, 'proc_umask', 'proc/umask.h', '<sys/stat.h>',
    'apos_mode_t', ['apos_mode_t:cmask:u'])

AddSyscall('setsid', 56, 'proc_setsid', 'proc/session.h', '<unistd.h>',
    'apos_pid_t', [])

AddSyscall('getsid', 57, 'proc_getsid', 'proc/session.h', '<unistd.h>',
    'apos_pid_t', ['apos_pid_t:pid:u'])

AddSyscall('tcgetpgrp', 58, 'proc_tcgetpgrp', 'proc/tcgroup.h', '<unistd.h>',
    'apos_pid_t', ['int:fd:u'])

AddSyscall('tcsetpgrp', 59, 'proc_tcsetpgrp', 'proc/tcgroup.h', '<unistd.h>',
    'int', ['int:fd:u', 'apos_pid_t:pgid:u'])

AddSyscall('tcgetsid', 60, 'proc_tcgetsid', 'proc/tcgroup.h', '<termios.h>',
    'apos_pid_t', ['int:fd:u'])

AddSyscall('tcdrain', 63, 'tty_tcdrain', 'dev/termios.h', '<termios.h>',
    'int', ['int:fd:u'])

AddSyscall('tcflush', 64, 'tty_tcflush', 'dev/termios.h', '<termios.h>',
    'int', ['int:fd:u', 'int:action:u'])

AddSyscall('tcgetattr', 65, 'tty_tcgetattr', 'dev/termios.h', '<termios.h>',
    'int', ['int:fd:u', 'struct ktermios*:t:bw:sizeof(struct ktermios)'])

AddSyscall('tcsetattr', 66, 'tty_tcsetattr', 'dev/termios.h', '<termios.h>',
    'int', ['int:fd:u', 'int:optional_actions:u',
      'const struct ktermios*:t:br:sizeof(struct ktermios)'])

AddSyscall('ftruncate', 67, 'vfs_ftruncate', 'vfs/vfs.h', '<unistd.h>',
    'int', ['int:fd:u', 'apos_off_t:length:u'])

AddSyscall('truncate', 68, 'vfs_truncate', 'vfs/vfs.h', '<unistd.h>',
    'int', ['const char*:path:s', 'apos_off_t:length:u'])

AddSyscall('poll', 69, 'vfs_poll', 'vfs/poll.h', '<poll.h>',
    'int', ['struct apos_pollfd*:fds:brw:sizeof(struct apos_pollfd) * nfds',
            'apos_nfds_t:nfds:u', 'int:timeout:u'])

AddSyscall('getrlimit', 75, 'proc_getrlimit', 'proc/limit.h',
    '<sys/resource.h>', 'int',
    ['int:resource:u',
      'struct apos_rlimit%(s32)s*:lim:bw:sizeof(struct apos_rlimit)'],
    needs_32bit_conv=True)

AddSyscall('setrlimit', 76, 'proc_setrlimit', 'proc/limit.h',
    '<sys/resource.h>', 'int',
    ['int:resource:u',
      'const struct apos_rlimit%(s32)s*:lim:br:sizeof(struct apos_rlimit)'],
    needs_32bit_conv=True)

AddSyscall('socket', 77, 'net_socket', 'net/socket/socket.h',
    '<sys/socket.h>', 'int',
    ['int:domain:u', 'int:type:u', 'int:protocol:u'])

AddSyscall('shutdown', 78, 'net_shutdown', 'net/socket/socket.h',
    '<sys/socket.h>', 'int',
    ['int:socket:u', 'int:how:u'])

AddSyscall('bind', 79, 'net_bind', 'net/socket/socket.h',
    '<sys/socket.h>', 'int',
    ['int:socket:u', 'const struct sockaddr*:addr:br:addr_len',
      'socklen_t:addr_len:u'])

AddSyscall('listen', 80, 'net_listen', 'net/socket/socket.h',
    '<sys/socket.h>', 'int',
    ['int:socket:u', 'int:backlog:u'])

AddSyscall('accept', 81, 'accept_wrapper', 'net/socket/socket.h',
    '<sys/socket.h>', 'int',
    ['int:socket:u', 'struct sockaddr*:addr:u',
      'socklen_t*:addr_len:brw?:sizeof(socklen_t)'])

AddSyscall('connect', 82, 'net_connect', 'net/socket/socket.h',
    '<sys/socket.h>', 'int',
    ['int:socket:u', 'const struct sockaddr*:addr:br:addr_len',
     'socklen_t:addr_len:u'])

AddSyscall('recv', 83, 'net_recv', 'net/socket/socket.h',
    '<sys/socket.h>', 'ssize_t',
    ['int:socket:u', 'void*:buf:bw:len', 'size_t:len:u', 'int:flags:u'])

AddSyscall('recvfrom', 84, 'recvfrom_wrapper', 'net/socket/socket.h',
    '<sys/socket.h>', 'ssize_t',
    ['int:socket:u', 'void*:buf:bw:len', 'size_t:len:u', 'int:flags:u',
      'struct sockaddr*:address:u',
      'socklen_t*:address_len:brw?:sizeof(socklen_t)'])

AddSyscall('send', 85, 'net_send', 'net/socket/socket.h',
    '<sys/socket.h>', 'ssize_t',
    ['int:socket:u', 'const void*:buf:br:len', 'size_t:len:u', 'int:flags:u'])

AddSyscall('sendto', 86, 'net_sendto', 'net/socket/socket.h',
    '<sys/socket.h>', 'ssize_t',
    ['int:socket:u', 'const void*:buf:br:len', 'size_t:len:u', 'int:flags:u',
      'const struct sockaddr*:dest_addr:br?:dest_len', 'socklen_t:dest_len:u'])

AddSyscall('apos_klog', 87, 'klog_wrapper', 'syscall/wrappers.h',
           '', 'int', ['const char*:msg:s'], can_fail=False)

AddSyscall('apos_run_ktest', 88, 'kernel_run_ktest', 'test/kernel_tests.h',
    '', 'int', ['const char*:name:s'])

AddSyscall('apos_thread_create', 89, 'proc_thread_create_user',
           'proc/user_thread.h', 'apos/thread.h', 'int',
           ['apos_uthread_id_t*:id:bw:sizeof(apos_uthread_id_t)',
            'void*:stack:u', 'void*:entry:u'])

AddSyscall('apos_thread_exit', 90, 'proc_thread_exit_user',
           'proc/process.h', '', 'int', [], can_fail=False)

AddSyscall('sigwait', 91, 'proc_sigwait', 'proc/signal/signal.h', '<signal.h>',
           'int', ['const ksigset_t*:sigmask:br:sizeof(ksigset_t)',
             'int*:sig:bw:sizeof(int)'])

AddSyscall('apos_thread_kill', 92, 'proc_thread_kill_user',
           'proc/user_thread.h', 'apos/thread.h', 'int',
           ['const apos_uthread_id_t*:id:br:sizeof(apos_uthread_id_t)',
            'int:sig:u'])

AddSyscall('apos_thread_self', 93, 'proc_thread_self',
           'proc/user_thread.h', 'apos/thread.h', 'int',
           ['apos_uthread_id_t*:id:bw:sizeof(apos_uthread_id_t)'])

AddSyscall('futex_ts', 94, 'futex_op', 'proc/futex.h', 'apos/futex.h',
           'int', ['uint32_t*:uaddr:u', 'int:op:u', 'uint32_t:val:u',
                   'const struct apos_timespec%(s32)s*:timespec:br?:' +
                   'sizeof(struct apos_timespec%(s32)s)', 'uint32_t*:uaddr2:u',
                   'uint32_t:val3:u'])

AddSyscall('mount', 95, 'vfs_mount', 'vfs/mount.h', '', 'int',
    ['const char*:source:s', 'const char*:mount_path:s',
      'const char*:type:s', 'unsigned long:flags:u',
      'const void*:data:br?:data_len', 'size_t:data_len:u'])

AddSyscall('unmount', 96, 'vfs_unmount', 'vfs/mount.h', '', 'int',
    ['const char*:mount_path:s', 'unsigned long:flags:u'])
