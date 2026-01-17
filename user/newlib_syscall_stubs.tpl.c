// Copyright 2014 Andrew Oates.  All Rights Reserved.
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

#include <reent.h>

#if __APOS_BUILDING_IN_TREE__
#include "user/include/apos/syscall.h"
#include "user/include/apos/syscalls.h"
#else
#include <apos/syscall.h>
#include <apos/syscalls.h>
#endif

#include <apos/ktest.h>
#include <apos/sleep.h>
#include <apos/syscall_decls.h>
#include <apos/test.h>
#include <dirent.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

#include "apos/futex.h"
#include "apos/thread.h"

static inline long _do_syscall_test(long arg1, long arg2, long arg3, long arg4,
                                    long arg5, long arg6) {
  long result;
  result = do_syscall(SYS_SYSCALL_TEST, (long)arg1, (long)arg2, (long)arg3,
                      (long)arg4, (long)arg5, (long)arg6);

  return result;
}

static inline int _do_open(const char* path, int flags, apos_mode_t mode) {
  int result;
  do {
    result = do_syscall(SYS_OPEN, (long)path, (long)flags, (long)mode, 0, 0, 0);

  } while (result == -EINTR_RESTART);
  return result;
}

static inline int _do_close(int fd) {
  int result;
  do {
    result = do_syscall(SYS_CLOSE, (long)fd, 0, 0, 0, 0, 0);

  } while (result == -EINTR_RESTART);
  return result;
}

static inline int _do_dup(int fd) {
  int result;
  do {
    result = do_syscall(SYS_DUP, (long)fd, 0, 0, 0, 0, 0);

  } while (result == -EINTR_RESTART);
  return result;
}

static inline int _do_dup2(int fd1, int fd2) {
  int result;
  do {
    result = do_syscall(SYS_DUP2, (long)fd1, (long)fd2, 0, 0, 0, 0);

  } while (result == -EINTR_RESTART);
  return result;
}

static inline int _do_mkdir(const char* path, apos_mode_t mode) {
  int result;
  do {
    result = do_syscall(SYS_MKDIR, (long)path, (long)mode, 0, 0, 0, 0);

  } while (result == -EINTR_RESTART);
  return result;
}

static inline int _do_mknod(const char* path, apos_mode_t mode,
                            apos_dev_t dev) {
  int result;
  do {
    result = do_syscall(SYS_MKNOD, (long)path, (long)mode, (long)dev, 0, 0, 0);

  } while (result == -EINTR_RESTART);
  return result;
}

static inline int _do_rmdir(const char* path) {
  int result;
  do {
    result = do_syscall(SYS_RMDIR, (long)path, 0, 0, 0, 0, 0);

  } while (result == -EINTR_RESTART);
  return result;
}

static inline int _do_link(const char* path1, const char* path2) {
  int result;
  do {
    result = do_syscall(SYS_LINK, (long)path1, (long)path2, 0, 0, 0, 0);

  } while (result == -EINTR_RESTART);
  return result;
}

static inline int _do_rename(const char* path1, const char* path2) {
  int result;
  do {
    result = do_syscall(SYS_RENAME, (long)path1, (long)path2, 0, 0, 0, 0);

  } while (result == -EINTR_RESTART);
  return result;
}

static inline int _do_unlink(const char* path) {
  int result;
  do {
    result = do_syscall(SYS_UNLINK, (long)path, 0, 0, 0, 0, 0);

  } while (result == -EINTR_RESTART);
  return result;
}

static inline ssize_t _do_read(int fd, void* buf, size_t count) {
  ssize_t result;
  do {
    result = do_syscall(SYS_READ, (long)fd, (long)buf, (long)count, 0, 0, 0);

  } while (result == -EINTR_RESTART);
  return result;
}

static inline ssize_t _do_write(int fd, const void* buf, size_t count) {
  ssize_t result;
  do {
    result = do_syscall(SYS_WRITE, (long)fd, (long)buf, (long)count, 0, 0, 0);

  } while (result == -EINTR_RESTART);
  return result;
}

static inline int _do_getdents(int fd, kdirent_t* buf, int count) {
  int result;
  do {
    result =
        do_syscall(SYS_GETDENTS, (long)fd, (long)buf, (long)count, 0, 0, 0);

  } while (result == -EINTR_RESTART);
  return result;
}

static inline int _do_getcwd(char* path_out, size_t size) {
  int result;
  do {
    result = do_syscall(SYS_GETCWD, (long)path_out, (long)size, 0, 0, 0, 0);

  } while (result == -EINTR_RESTART);
  return result;
}

static inline int _do_stat(const char* path, apos_stat_t* stat) {
  int result;
  do {
    result = do_syscall(SYS_STAT, (long)path, (long)stat, 0, 0, 0, 0);

  } while (result == -EINTR_RESTART);
  return result;
}

static inline int _do_lstat(const char* path, apos_stat_t* stat) {
  int result;
  do {
    result = do_syscall(SYS_LSTAT, (long)path, (long)stat, 0, 0, 0, 0);

  } while (result == -EINTR_RESTART);
  return result;
}

static inline int _do_fstat(int fd, apos_stat_t* stat) {
  int result;
  do {
    result = do_syscall(SYS_FSTAT, (long)fd, (long)stat, 0, 0, 0, 0);

  } while (result == -EINTR_RESTART);
  return result;
}

static inline apos_off_t _do_lseek(int fd, apos_off_t offset, int whence) {
  apos_off_t result;
  do {
    result =
        do_syscall(SYS_LSEEK, (long)fd, (long)offset, (long)whence, 0, 0, 0);

  } while (result == -EINTR_RESTART);
  return result;
}

static inline int _do_chdir(const char* path) {
  int result;
  do {
    result = do_syscall(SYS_CHDIR, (long)path, 0, 0, 0, 0, 0);

  } while (result == -EINTR_RESTART);
  return result;
}

static inline int _do_access(const char* path, int amode) {
  int result;
  do {
    result = do_syscall(SYS_ACCESS, (long)path, (long)amode, 0, 0, 0, 0);

  } while (result == -EINTR_RESTART);
  return result;
}

static inline int _do_chown(const char* path, apos_uid_t owner,
                            apos_gid_t group) {
  int result;
  do {
    result =
        do_syscall(SYS_CHOWN, (long)path, (long)owner, (long)group, 0, 0, 0);

  } while (result == -EINTR_RESTART);
  return result;
}

static inline int _do_fchown(int fd, apos_uid_t owner, apos_gid_t group) {
  int result;
  do {
    result =
        do_syscall(SYS_FCHOWN, (long)fd, (long)owner, (long)group, 0, 0, 0);

  } while (result == -EINTR_RESTART);
  return result;
}

static inline int _do_lchown(const char* path, apos_uid_t owner,
                             apos_gid_t group) {
  int result;
  do {
    result =
        do_syscall(SYS_LCHOWN, (long)path, (long)owner, (long)group, 0, 0, 0);

  } while (result == -EINTR_RESTART);
  return result;
}

static inline int _do_chmod(const char* path, apos_mode_t mode) {
  int result;
  do {
    result = do_syscall(SYS_CHMOD, (long)path, (long)mode, 0, 0, 0, 0);

  } while (result == -EINTR_RESTART);
  return result;
}

static inline int _do_fchmod(int fd, apos_mode_t mode) {
  int result;
  do {
    result = do_syscall(SYS_FCHMOD, (long)fd, (long)mode, 0, 0, 0, 0);

  } while (result == -EINTR_RESTART);
  return result;
}

static inline int _do_fcntl(int fd, int cmd, int arg) {
  int result;
  do {
    result = do_syscall(SYS_FCNTL, (long)fd, (long)cmd, (long)arg, 0, 0, 0);

  } while (result == -EINTR_RESTART);
  return result;
}

static inline apos_pid_t _do_fork(void) {
  apos_pid_t result;
  do {
    result = do_syscall(SYS_FORK, 0, 0, 0, 0, 0, 0);

  } while (result == -EINTR_RESTART);
  return result;
}

static inline apos_pid_t _do_vfork(void) {
  apos_pid_t result;
  do {
    result = do_syscall(SYS_VFORK, 0, 0, 0, 0, 0, 0);

  } while (result == -EINTR_RESTART);
  return result;
}

static inline int _do_exit(int status) {
  int result;
  result = do_syscall(SYS_EXIT, (long)status, 0, 0, 0, 0, 0);

  return result;
}

static inline apos_pid_t _do_wait(int* exit_status) {
  apos_pid_t result;
  do {
    result = do_syscall(SYS_WAIT, (long)exit_status, 0, 0, 0, 0, 0);

  } while (result == -EINTR_RESTART);
  return result;
}

static inline apos_pid_t _do_waitpid(apos_pid_t child, int* exit_status,
                                     int options) {
  apos_pid_t result;
  do {
    result = do_syscall(SYS_WAITPID, (long)child, (long)exit_status,
                        (long)options, 0, 0, 0);

  } while (result == -EINTR_RESTART);
  return result;
}

static inline int _do_execve(const char* path, char* const* argv,
                             char* const* envp) {
  int result;
  do {
    result =
        do_syscall(SYS_EXECVE, (long)path, (long)argv, (long)envp, 0, 0, 0);

  } while (result == -EINTR_RESTART);
  return result;
}

static inline apos_pid_t _do_getpid(void) {
  apos_pid_t result;
  result = do_syscall(SYS_GETPID, 0, 0, 0, 0, 0, 0);

  return result;
}

static inline apos_pid_t _do_getppid(void) {
  apos_pid_t result;
  result = do_syscall(SYS_GETPPID, 0, 0, 0, 0, 0, 0);

  return result;
}

static inline int _do_isatty(int fd) {
  int result;
  do {
    result = do_syscall(SYS_ISATTY, (long)fd, 0, 0, 0, 0, 0);

  } while (result == -EINTR_RESTART);
  return result;
}

static inline int _do_kill(apos_pid_t pid, int sig) {
  int result;
  do {
    result = do_syscall(SYS_KILL, (long)pid, (long)sig, 0, 0, 0, 0);

  } while (result == -EINTR_RESTART);
  return result;
}

static inline int _do_sigaction(int signum, const struct ksigaction* act,
                                struct ksigaction* oldact) {
  int result;
  do {
    result = do_syscall(SYS_SIGACTION, (long)signum, (long)act, (long)oldact, 0,
                        0, 0);

  } while (result == -EINTR_RESTART);
  return result;
}

static inline int _do_sigprocmask(int how, const ksigset_t* set,
                                  ksigset_t* oset) {
  int result;
  do {
    result =
        do_syscall(SYS_SIGPROCMASK, (long)how, (long)set, (long)oset, 0, 0, 0);

  } while (result == -EINTR_RESTART);
  return result;
}

static inline int _do_sigpending(ksigset_t* oset) {
  int result;
  do {
    result = do_syscall(SYS_SIGPENDING, (long)oset, 0, 0, 0, 0, 0);

  } while (result == -EINTR_RESTART);
  return result;
}

static inline int _do_sigsuspend(const ksigset_t* sigmask) {
  int result;
  do {
    result = do_syscall(SYS_SIGSUSPEND, (long)sigmask, 0, 0, 0, 0, 0);

  } while (result == -EINTR_RESTART);
  return result;
}

static inline unsigned int _do_alarm_ms(unsigned int seconds) {
  unsigned int result;
  result = do_syscall(SYS_ALARM_MS, (long)seconds, 0, 0, 0, 0, 0);

  return result;
}

static inline int _do_setuid(apos_uid_t uid) {
  int result;
  do {
    result = do_syscall(SYS_SETUID, (long)uid, 0, 0, 0, 0, 0);

  } while (result == -EINTR_RESTART);
  return result;
}

static inline int _do_setgid(apos_gid_t gid) {
  int result;
  do {
    result = do_syscall(SYS_SETGID, (long)gid, 0, 0, 0, 0, 0);

  } while (result == -EINTR_RESTART);
  return result;
}

static inline apos_uid_t _do_getuid(void) {
  apos_uid_t result;
  result = do_syscall(SYS_GETUID, 0, 0, 0, 0, 0, 0);

  return result;
}

static inline apos_gid_t _do_getgid(void) {
  apos_gid_t result;
  result = do_syscall(SYS_GETGID, 0, 0, 0, 0, 0, 0);

  return result;
}

static inline int _do_seteuid(apos_uid_t uid) {
  int result;
  do {
    result = do_syscall(SYS_SETEUID, (long)uid, 0, 0, 0, 0, 0);

  } while (result == -EINTR_RESTART);
  return result;
}

static inline int _do_setegid(apos_gid_t gid) {
  int result;
  do {
    result = do_syscall(SYS_SETEGID, (long)gid, 0, 0, 0, 0, 0);

  } while (result == -EINTR_RESTART);
  return result;
}

static inline apos_uid_t _do_geteuid(void) {
  apos_uid_t result;
  result = do_syscall(SYS_GETEUID, 0, 0, 0, 0, 0, 0);

  return result;
}

static inline apos_gid_t _do_getegid(void) {
  apos_gid_t result;
  result = do_syscall(SYS_GETEGID, 0, 0, 0, 0, 0, 0);

  return result;
}

static inline int _do_setreuid(apos_uid_t ruid, apos_uid_t euid) {
  int result;
  do {
    result = do_syscall(SYS_SETREUID, (long)ruid, (long)euid, 0, 0, 0, 0);

  } while (result == -EINTR_RESTART);
  return result;
}

static inline int _do_setregid(apos_gid_t rgid, apos_gid_t egid) {
  int result;
  do {
    result = do_syscall(SYS_SETREGID, (long)rgid, (long)egid, 0, 0, 0, 0);

  } while (result == -EINTR_RESTART);
  return result;
}

static inline apos_pid_t _do_getpgid(apos_pid_t pid) {
  apos_pid_t result;
  do {
    result = do_syscall(SYS_GETPGID, (long)pid, 0, 0, 0, 0, 0);

  } while (result == -EINTR_RESTART);
  return result;
}

static inline int _do_setpgid(apos_pid_t pid, apos_pid_t pgid) {
  int result;
  do {
    result = do_syscall(SYS_SETPGID, (long)pid, (long)pgid, 0, 0, 0, 0);

  } while (result == -EINTR_RESTART);
  return result;
}

static inline int _do_mmap(void* addr_inout, size_t length, int prot, int flags,
                           int fd, apos_off_t offset) {
  int result;
  do {
    result = do_syscall(SYS_MMAP, (long)addr_inout, (long)length, (long)prot,
                        (long)flags, (long)fd, (long)offset);

  } while (result == -EINTR_RESTART);
  return result;
}

static inline int _do_munmap(void* addr, size_t length) {
  int result;
  do {
    result = do_syscall(SYS_MUNMAP, (long)addr, (long)length, 0, 0, 0, 0);

  } while (result == -EINTR_RESTART);
  return result;
}

static inline int _do_symlink(const char* path1, const char* path2) {
  int result;
  do {
    result = do_syscall(SYS_SYMLINK, (long)path1, (long)path2, 0, 0, 0, 0);

  } while (result == -EINTR_RESTART);
  return result;
}

static inline int _do_readlink(const char* path, char* buf, size_t bufsize) {
  int result;
  do {
    result =
        do_syscall(SYS_READLINK, (long)path, (long)buf, (long)bufsize, 0, 0, 0);

  } while (result == -EINTR_RESTART);
  return result;
}

static inline int _do_sleep_ms(int milliseconds) {
  int result;
  do {
    result = do_syscall(SYS_SLEEP_MS, (long)milliseconds, 0, 0, 0, 0, 0);

  } while (result == -EINTR_RESTART);
  return result;
}

static inline int _do_apos_get_time(struct apos_tm* t) {
  int result;
  do {
    result = do_syscall(SYS_APOS_GET_TIME, (long)t, 0, 0, 0, 0, 0);

  } while (result == -EINTR_RESTART);
  return result;
}

static inline int _do_apos_get_timespec(struct apos_timespec* t) {
  int result;
  do {
    result = do_syscall(SYS_APOS_GET_TIMESPEC, (long)t, 0, 0, 0, 0, 0);

  } while (result == -EINTR_RESTART);
  return result;
}

static inline int _do_pipe(int* fildes) {
  int result;
  do {
    result = do_syscall(SYS_PIPE, (long)fildes, 0, 0, 0, 0, 0);

  } while (result == -EINTR_RESTART);
  return result;
}

static inline apos_mode_t _do_umask(apos_mode_t cmask) {
  apos_mode_t result;
  do {
    result = do_syscall(SYS_UMASK, (long)cmask, 0, 0, 0, 0, 0);

  } while (result == -EINTR_RESTART);
  return result;
}

static inline apos_pid_t _do_setsid(void) {
  apos_pid_t result;
  do {
    result = do_syscall(SYS_SETSID, 0, 0, 0, 0, 0, 0);

  } while (result == -EINTR_RESTART);
  return result;
}

static inline apos_pid_t _do_getsid(apos_pid_t pid) {
  apos_pid_t result;
  do {
    result = do_syscall(SYS_GETSID, (long)pid, 0, 0, 0, 0, 0);

  } while (result == -EINTR_RESTART);
  return result;
}

static inline apos_pid_t _do_tcgetpgrp(int fd) {
  apos_pid_t result;
  do {
    result = do_syscall(SYS_TCGETPGRP, (long)fd, 0, 0, 0, 0, 0);

  } while (result == -EINTR_RESTART);
  return result;
}

static inline int _do_tcsetpgrp(int fd, apos_pid_t pgid) {
  int result;
  do {
    result = do_syscall(SYS_TCSETPGRP, (long)fd, (long)pgid, 0, 0, 0, 0);

  } while (result == -EINTR_RESTART);
  return result;
}

static inline apos_pid_t _do_tcgetsid(int fd) {
  apos_pid_t result;
  do {
    result = do_syscall(SYS_TCGETSID, (long)fd, 0, 0, 0, 0, 0);

  } while (result == -EINTR_RESTART);
  return result;
}

static inline int _do_tcdrain(int fd) {
  int result;
  do {
    result = do_syscall(SYS_TCDRAIN, (long)fd, 0, 0, 0, 0, 0);

  } while (result == -EINTR_RESTART);
  return result;
}

static inline int _do_tcflush(int fd, int action) {
  int result;
  do {
    result = do_syscall(SYS_TCFLUSH, (long)fd, (long)action, 0, 0, 0, 0);

  } while (result == -EINTR_RESTART);
  return result;
}

static inline int _do_tcgetattr(int fd, struct ktermios* t) {
  int result;
  do {
    result = do_syscall(SYS_TCGETATTR, (long)fd, (long)t, 0, 0, 0, 0);

  } while (result == -EINTR_RESTART);
  return result;
}

static inline int _do_tcsetattr(int fd, int optional_actions,
                                const struct ktermios* t) {
  int result;
  do {
    result = do_syscall(SYS_TCSETATTR, (long)fd, (long)optional_actions,
                        (long)t, 0, 0, 0);

  } while (result == -EINTR_RESTART);
  return result;
}

static inline int _do_ftruncate(int fd, apos_off_t length) {
  int result;
  do {
    result = do_syscall(SYS_FTRUNCATE, (long)fd, (long)length, 0, 0, 0, 0);

  } while (result == -EINTR_RESTART);
  return result;
}

static inline int _do_truncate(const char* path, apos_off_t length) {
  int result;
  do {
    result = do_syscall(SYS_TRUNCATE, (long)path, (long)length, 0, 0, 0, 0);

  } while (result == -EINTR_RESTART);
  return result;
}

static inline int _do_poll(struct apos_pollfd* fds, apos_nfds_t nfds,
                           int timeout) {
  int result;
  do {
    result =
        do_syscall(SYS_POLL, (long)fds, (long)nfds, (long)timeout, 0, 0, 0);

  } while (result == -EINTR_RESTART);
  return result;
}

static inline int _do_getrlimit(int resource, struct apos_rlimit* lim) {
  int result;
  do {
    result = do_syscall(SYS_GETRLIMIT, (long)resource, (long)lim, 0, 0, 0, 0);

  } while (result == -EINTR_RESTART);
  return result;
}

static inline int _do_setrlimit(int resource, const struct apos_rlimit* lim) {
  int result;
  do {
    result = do_syscall(SYS_SETRLIMIT, (long)resource, (long)lim, 0, 0, 0, 0);

  } while (result == -EINTR_RESTART);
  return result;
}

static inline int _do_socket(int domain, int type, int protocol) {
  int result;
  do {
    result = do_syscall(SYS_SOCKET, (long)domain, (long)type, (long)protocol, 0,
                        0, 0);

  } while (result == -EINTR_RESTART);
  return result;
}

static inline int _do_shutdown(int socket, int how) {
  int result;
  do {
    result = do_syscall(SYS_SHUTDOWN, (long)socket, (long)how, 0, 0, 0, 0);

  } while (result == -EINTR_RESTART);
  return result;
}

static inline int _do_bind(int socket, const struct sockaddr* addr,
                           socklen_t addr_len) {
  int result;
  do {
    result =
        do_syscall(SYS_BIND, (long)socket, (long)addr, (long)addr_len, 0, 0, 0);

  } while (result == -EINTR_RESTART);
  return result;
}

static inline int _do_listen(int socket, int backlog) {
  int result;
  do {
    result = do_syscall(SYS_LISTEN, (long)socket, (long)backlog, 0, 0, 0, 0);

  } while (result == -EINTR_RESTART);
  return result;
}

static inline int _do_accept(int socket, struct sockaddr* addr,
                             socklen_t* addr_len) {
  int result;
  do {
    result = do_syscall(SYS_ACCEPT, (long)socket, (long)addr, (long)addr_len, 0,
                        0, 0);

  } while (result == -EINTR_RESTART);
  return result;
}

static inline int _do_connect(int socket, const struct sockaddr* addr,
                              socklen_t addr_len) {
  int result;
  do {
    result = do_syscall(SYS_CONNECT, (long)socket, (long)addr, (long)addr_len,
                        0, 0, 0);

  } while (result == -EINTR_RESTART);
  return result;
}

static inline ssize_t _do_recv(int socket, void* buf, size_t len, int flags) {
  ssize_t result;
  do {
    result = do_syscall(SYS_RECV, (long)socket, (long)buf, (long)len,
                        (long)flags, 0, 0);

  } while (result == -EINTR_RESTART);
  return result;
}

static inline ssize_t _do_recvfrom(int socket, void* buf, size_t len, int flags,
                                   struct sockaddr* address,
                                   socklen_t* address_len) {
  ssize_t result;
  do {
    result = do_syscall(SYS_RECVFROM, (long)socket, (long)buf, (long)len,
                        (long)flags, (long)address, (long)address_len);

  } while (result == -EINTR_RESTART);
  return result;
}

static inline ssize_t _do_send(int socket, const void* buf, size_t len,
                               int flags) {
  ssize_t result;
  do {
    result = do_syscall(SYS_SEND, (long)socket, (long)buf, (long)len,
                        (long)flags, 0, 0);

  } while (result == -EINTR_RESTART);
  return result;
}

static inline ssize_t _do_sendto(int socket, const void* buf, size_t len,
                                 int flags, const struct sockaddr* dest_addr,
                                 socklen_t dest_len) {
  ssize_t result;
  do {
    result = do_syscall(SYS_SENDTO, (long)socket, (long)buf, (long)len,
                        (long)flags, (long)dest_addr, (long)dest_len);

  } while (result == -EINTR_RESTART);
  return result;
}

static inline int _do_apos_klog(const char* msg) {
  int result;
  result = do_syscall(SYS_APOS_KLOG, (long)msg, 0, 0, 0, 0, 0);

  return result;
}

static inline int _do_apos_run_ktest(const char* name) {
  int result;
  do {
    result = do_syscall(SYS_APOS_RUN_KTEST, (long)name, 0, 0, 0, 0, 0);

  } while (result == -EINTR_RESTART);
  return result;
}

static inline int _do_apos_run_ktests(const apos_ktest_t* tests, size_t num) {
  int result;
  do {
    result =
        do_syscall(SYS_APOS_RUN_KTESTS, (long)tests, (long)num, 0, 0, 0, 0);

  } while (result == -EINTR_RESTART);
  return result;
}

static inline int _do_apos_thread_create(apos_uthread_id_t* id, void* stack,
                                         void* entry) {
  int result;
  do {
    result = do_syscall(SYS_APOS_THREAD_CREATE, (long)id, (long)stack,
                        (long)entry, 0, 0, 0);

  } while (result == -EINTR_RESTART);
  return result;
}

static inline int _do_apos_thread_exit(void) {
  int result;
  result = do_syscall(SYS_APOS_THREAD_EXIT, 0, 0, 0, 0, 0, 0);

  return result;
}

static inline int _do_sigwait(const ksigset_t* sigmask, int* sig) {
  int result;
  do {
    result = do_syscall(SYS_SIGWAIT, (long)sigmask, (long)sig, 0, 0, 0, 0);

  } while (result == -EINTR_RESTART);
  return result;
}

static inline int _do_apos_thread_kill(const apos_uthread_id_t* id, int sig) {
  int result;
  do {
    result = do_syscall(SYS_APOS_THREAD_KILL, (long)id, (long)sig, 0, 0, 0, 0);

  } while (result == -EINTR_RESTART);
  return result;
}

static inline int _do_apos_thread_self(apos_uthread_id_t* id) {
  int result;
  do {
    result = do_syscall(SYS_APOS_THREAD_SELF, (long)id, 0, 0, 0, 0, 0);

  } while (result == -EINTR_RESTART);
  return result;
}

static inline int _do_futex_ts(uint32_t* uaddr, int op, uint32_t val,
                               const struct apos_timespec* timespec,
                               uint32_t* uaddr2, uint32_t val3) {
  int result;
  do {
    result = do_syscall(SYS_FUTEX_TS, (long)uaddr, (long)op, (long)val,
                        (long)timespec, (long)uaddr2, (long)val3);

  } while (result == -EINTR_RESTART);
  return result;
}

static inline int _do_mount(const char* source, const char* mount_path,
                            const char* type, unsigned long flags,
                            const void* data, size_t data_len) {
  int result;
  do {
    result = do_syscall(SYS_MOUNT, (long)source, (long)mount_path, (long)type,
                        (long)flags, (long)data, (long)data_len);

  } while (result == -EINTR_RESTART);
  return result;
}

static inline int _do_unmount(const char* mount_path, unsigned long flags) {
  int result;
  do {
    result = do_syscall(SYS_UNMOUNT, (long)mount_path, (long)flags, 0, 0, 0, 0);

  } while (result == -EINTR_RESTART);
  return result;
}

static inline int _do_getsockopt(int socket, int level, int option, void* val,
                                 socklen_t* val_len) {
  int result;
  do {
    result = do_syscall(SYS_GETSOCKOPT, (long)socket, (long)level, (long)option,
                        (long)val, (long)val_len, 0);

  } while (result == -EINTR_RESTART);
  return result;
}

static inline int _do_setsockopt(int socket, int level, int option,
                                 const void* val, socklen_t val_len) {
  int result;
  do {
    result = do_syscall(SYS_SETSOCKOPT, (long)socket, (long)level, (long)option,
                        (long)val, (long)val_len, 0);

  } while (result == -EINTR_RESTART);
  return result;
}

static inline int _do_getsockname(int socket, struct sockaddr* address,
                                  socklen_t* len) {
  int result;
  do {
    result = do_syscall(SYS_GETSOCKNAME, (long)socket, (long)address, (long)len,
                        0, 0, 0);

  } while (result == -EINTR_RESTART);
  return result;
}

static inline int _do_getpeername(int socket, struct sockaddr* address,
                                  socklen_t* len) {
  int result;
  do {
    result = do_syscall(SYS_GETPEERNAME, (long)socket, (long)address, (long)len,
                        0, 0, 0);

  } while (result == -EINTR_RESTART);
  return result;
}

long _syscall_test_r(struct _reent* reent_ptr, long arg1, long arg2, long arg3,
                     long arg4, long arg5, long arg6) {
  long result = _do_syscall_test(arg1, arg2, arg3, arg4, arg5, arg6);
  return result;
}

int _open_r(struct _reent* reent_ptr, const char* path, int flags,
            apos_mode_t mode) {
  int result = _do_open(path, flags, mode);
  if (result < 0) {
    reent_ptr->_errno = -result;
    result = -1;
  }
  return result;
}

int _close_r(struct _reent* reent_ptr, int fd) {
  int result = _do_close(fd);
  if (result < 0) {
    reent_ptr->_errno = -result;
    result = -1;
  }
  return result;
}

int _dup_r(struct _reent* reent_ptr, int fd) {
  int result = _do_dup(fd);
  if (result < 0) {
    reent_ptr->_errno = -result;
    result = -1;
  }
  return result;
}

int _dup2_r(struct _reent* reent_ptr, int fd1, int fd2) {
  int result = _do_dup2(fd1, fd2);
  if (result < 0) {
    reent_ptr->_errno = -result;
    result = -1;
  }
  return result;
}

int _mkdir_r(struct _reent* reent_ptr, const char* path, apos_mode_t mode) {
  int result = _do_mkdir(path, mode);
  if (result < 0) {
    reent_ptr->_errno = -result;
    result = -1;
  }
  return result;
}

int _mknod_r(struct _reent* reent_ptr, const char* path, apos_mode_t mode,
             apos_dev_t dev) {
  int result = _do_mknod(path, mode, dev);
  if (result < 0) {
    reent_ptr->_errno = -result;
    result = -1;
  }
  return result;
}

int _rmdir_r(struct _reent* reent_ptr, const char* path) {
  int result = _do_rmdir(path);
  if (result < 0) {
    reent_ptr->_errno = -result;
    result = -1;
  }
  return result;
}

int _link_r(struct _reent* reent_ptr, const char* path1, const char* path2) {
  int result = _do_link(path1, path2);
  if (result < 0) {
    reent_ptr->_errno = -result;
    result = -1;
  }
  return result;
}

int _rename_r(struct _reent* reent_ptr, const char* path1, const char* path2) {
  int result = _do_rename(path1, path2);
  if (result < 0) {
    reent_ptr->_errno = -result;
    result = -1;
  }
  return result;
}

int _unlink_r(struct _reent* reent_ptr, const char* path) {
  int result = _do_unlink(path);
  if (result < 0) {
    reent_ptr->_errno = -result;
    result = -1;
  }
  return result;
}

ssize_t _read_r(struct _reent* reent_ptr, int fd, void* buf, size_t count) {
  ssize_t result = _do_read(fd, buf, count);
  if (result < 0) {
    reent_ptr->_errno = -result;
    result = -1;
  }
  return result;
}

ssize_t _write_r(struct _reent* reent_ptr, int fd, const void* buf,
                 size_t count) {
  ssize_t result = _do_write(fd, buf, count);
  if (result < 0) {
    reent_ptr->_errno = -result;
    result = -1;
  }
  return result;
}

int _getdents_r(struct _reent* reent_ptr, int fd, kdirent_t* buf, int count) {
  int result = _do_getdents(fd, buf, count);
  if (result < 0) {
    reent_ptr->_errno = -result;
    result = -1;
  }
  return result;
}

int _stat_r(struct _reent* reent_ptr, const char* path, apos_stat_t* stat) {
  int result = _do_stat(path, stat);
  if (result < 0) {
    reent_ptr->_errno = -result;
    result = -1;
  }
  return result;
}

int _lstat_r(struct _reent* reent_ptr, const char* path, apos_stat_t* stat) {
  int result = _do_lstat(path, stat);
  if (result < 0) {
    reent_ptr->_errno = -result;
    result = -1;
  }
  return result;
}

int _fstat_r(struct _reent* reent_ptr, int fd, apos_stat_t* stat) {
  int result = _do_fstat(fd, stat);
  if (result < 0) {
    reent_ptr->_errno = -result;
    result = -1;
  }
  return result;
}

apos_off_t _lseek_r(struct _reent* reent_ptr, int fd, apos_off_t offset,
                    int whence) {
  apos_off_t result = _do_lseek(fd, offset, whence);
  if (result < 0) {
    reent_ptr->_errno = -result;
    result = -1;
  }
  return result;
}

int _chdir_r(struct _reent* reent_ptr, const char* path) {
  int result = _do_chdir(path);
  if (result < 0) {
    reent_ptr->_errno = -result;
    result = -1;
  }
  return result;
}

int _access_r(struct _reent* reent_ptr, const char* path, int amode) {
  int result = _do_access(path, amode);
  if (result < 0) {
    reent_ptr->_errno = -result;
    result = -1;
  }
  return result;
}

int _chown_r(struct _reent* reent_ptr, const char* path, apos_uid_t owner,
             apos_gid_t group) {
  int result = _do_chown(path, owner, group);
  if (result < 0) {
    reent_ptr->_errno = -result;
    result = -1;
  }
  return result;
}

int _fchown_r(struct _reent* reent_ptr, int fd, apos_uid_t owner,
              apos_gid_t group) {
  int result = _do_fchown(fd, owner, group);
  if (result < 0) {
    reent_ptr->_errno = -result;
    result = -1;
  }
  return result;
}

int _lchown_r(struct _reent* reent_ptr, const char* path, apos_uid_t owner,
              apos_gid_t group) {
  int result = _do_lchown(path, owner, group);
  if (result < 0) {
    reent_ptr->_errno = -result;
    result = -1;
  }
  return result;
}

int _chmod_r(struct _reent* reent_ptr, const char* path, apos_mode_t mode) {
  int result = _do_chmod(path, mode);
  if (result < 0) {
    reent_ptr->_errno = -result;
    result = -1;
  }
  return result;
}

int _fchmod_r(struct _reent* reent_ptr, int fd, apos_mode_t mode) {
  int result = _do_fchmod(fd, mode);
  if (result < 0) {
    reent_ptr->_errno = -result;
    result = -1;
  }
  return result;
}

int _fcntl_r(struct _reent* reent_ptr, int fd, int cmd, int arg) {
  int result = _do_fcntl(fd, cmd, arg);
  if (result < 0) {
    reent_ptr->_errno = -result;
    result = -1;
  }
  return result;
}

apos_pid_t _fork_r(struct _reent* reent_ptr) {
  apos_pid_t result = _do_fork();
  if (result < 0) {
    reent_ptr->_errno = -result;
    result = -1;
  }
  return result;
}

apos_pid_t _vfork_r(struct _reent* reent_ptr) {
  apos_pid_t result = _do_vfork();
  if (result < 0) {
    reent_ptr->_errno = -result;
    result = -1;
  }
  return result;
}

apos_pid_t _wait_r(struct _reent* reent_ptr, int* exit_status) {
  apos_pid_t result = _do_wait(exit_status);
  if (result < 0) {
    reent_ptr->_errno = -result;
    result = -1;
  }
  return result;
}

apos_pid_t _waitpid_r(struct _reent* reent_ptr, apos_pid_t child,
                      int* exit_status, int options) {
  apos_pid_t result = _do_waitpid(child, exit_status, options);
  if (result < 0) {
    reent_ptr->_errno = -result;
    result = -1;
  }
  return result;
}

int _execve_r(struct _reent* reent_ptr, const char* path, char* const* argv,
              char* const* envp) {
  int result = _do_execve(path, argv, envp);
  if (result < 0) {
    reent_ptr->_errno = -result;
    result = -1;
  }
  return result;
}

apos_pid_t _getpid_r(struct _reent* reent_ptr) {
  apos_pid_t result = _do_getpid();
  return result;
}

apos_pid_t _getppid_r(struct _reent* reent_ptr) {
  apos_pid_t result = _do_getppid();
  return result;
}

int _isatty_r(struct _reent* reent_ptr, int fd) {
  int result = _do_isatty(fd);
  if (result < 0) {
    reent_ptr->_errno = -result;
    result = -1;
  }
  return result;
}

int _kill_r(struct _reent* reent_ptr, apos_pid_t pid, int sig) {
  int result = _do_kill(pid, sig);
  if (result < 0) {
    reent_ptr->_errno = -result;
    result = -1;
  }
  return result;
}

int _sigaction_r(struct _reent* reent_ptr, int signum,
                 const struct ksigaction* act, struct ksigaction* oldact) {
  int result = _do_sigaction(signum, act, oldact);
  if (result < 0) {
    reent_ptr->_errno = -result;
    result = -1;
  }
  return result;
}

int _sigprocmask_r(struct _reent* reent_ptr, int how, const ksigset_t* set,
                   ksigset_t* oset) {
  int result = _do_sigprocmask(how, set, oset);
  if (result < 0) {
    reent_ptr->_errno = -result;
    result = -1;
  }
  return result;
}

int _sigpending_r(struct _reent* reent_ptr, ksigset_t* oset) {
  int result = _do_sigpending(oset);
  if (result < 0) {
    reent_ptr->_errno = -result;
    result = -1;
  }
  return result;
}

int _sigsuspend_r(struct _reent* reent_ptr, const ksigset_t* sigmask) {
  int result = _do_sigsuspend(sigmask);
  if (result < 0) {
    reent_ptr->_errno = -result;
    result = -1;
  }
  return result;
}

unsigned int _alarm_ms_r(struct _reent* reent_ptr, unsigned int seconds) {
  unsigned int result = _do_alarm_ms(seconds);
  return result;
}

int _setuid_r(struct _reent* reent_ptr, apos_uid_t uid) {
  int result = _do_setuid(uid);
  if (result < 0) {
    reent_ptr->_errno = -result;
    result = -1;
  }
  return result;
}

int _setgid_r(struct _reent* reent_ptr, apos_gid_t gid) {
  int result = _do_setgid(gid);
  if (result < 0) {
    reent_ptr->_errno = -result;
    result = -1;
  }
  return result;
}

apos_uid_t _getuid_r(struct _reent* reent_ptr) {
  apos_uid_t result = _do_getuid();
  return result;
}

apos_gid_t _getgid_r(struct _reent* reent_ptr) {
  apos_gid_t result = _do_getgid();
  return result;
}

int _seteuid_r(struct _reent* reent_ptr, apos_uid_t uid) {
  int result = _do_seteuid(uid);
  if (result < 0) {
    reent_ptr->_errno = -result;
    result = -1;
  }
  return result;
}

int _setegid_r(struct _reent* reent_ptr, apos_gid_t gid) {
  int result = _do_setegid(gid);
  if (result < 0) {
    reent_ptr->_errno = -result;
    result = -1;
  }
  return result;
}

apos_uid_t _geteuid_r(struct _reent* reent_ptr) {
  apos_uid_t result = _do_geteuid();
  return result;
}

apos_gid_t _getegid_r(struct _reent* reent_ptr) {
  apos_gid_t result = _do_getegid();
  return result;
}

int _setreuid_r(struct _reent* reent_ptr, apos_uid_t ruid, apos_uid_t euid) {
  int result = _do_setreuid(ruid, euid);
  if (result < 0) {
    reent_ptr->_errno = -result;
    result = -1;
  }
  return result;
}

int _setregid_r(struct _reent* reent_ptr, apos_gid_t rgid, apos_gid_t egid) {
  int result = _do_setregid(rgid, egid);
  if (result < 0) {
    reent_ptr->_errno = -result;
    result = -1;
  }
  return result;
}

apos_pid_t _getpgid_r(struct _reent* reent_ptr, apos_pid_t pid) {
  apos_pid_t result = _do_getpgid(pid);
  if (result < 0) {
    reent_ptr->_errno = -result;
    result = -1;
  }
  return result;
}

int _setpgid_r(struct _reent* reent_ptr, apos_pid_t pid, apos_pid_t pgid) {
  int result = _do_setpgid(pid, pgid);
  if (result < 0) {
    reent_ptr->_errno = -result;
    result = -1;
  }
  return result;
}

int _munmap_r(struct _reent* reent_ptr, void* addr, size_t length) {
  int result = _do_munmap(addr, length);
  if (result < 0) {
    reent_ptr->_errno = -result;
    result = -1;
  }
  return result;
}

int _symlink_r(struct _reent* reent_ptr, const char* path1, const char* path2) {
  int result = _do_symlink(path1, path2);
  if (result < 0) {
    reent_ptr->_errno = -result;
    result = -1;
  }
  return result;
}

int _readlink_r(struct _reent* reent_ptr, const char* path, char* buf,
                size_t bufsize) {
  int result = _do_readlink(path, buf, bufsize);
  if (result < 0) {
    reent_ptr->_errno = -result;
    result = -1;
  }
  return result;
}

int _sleep_ms_r(struct _reent* reent_ptr, int milliseconds) {
  int result = _do_sleep_ms(milliseconds);
  if (result < 0) {
    reent_ptr->_errno = -result;
    result = -1;
  }
  return result;
}

int _apos_get_time_r(struct _reent* reent_ptr, struct apos_tm* t) {
  int result = _do_apos_get_time(t);
  if (result < 0) {
    reent_ptr->_errno = -result;
    result = -1;
  }
  return result;
}

int _apos_get_timespec_r(struct _reent* reent_ptr, struct apos_timespec* t) {
  int result = _do_apos_get_timespec(t);
  if (result < 0) {
    reent_ptr->_errno = -result;
    result = -1;
  }
  return result;
}

int _pipe_r(struct _reent* reent_ptr, int* fildes) {
  int result = _do_pipe(fildes);
  if (result < 0) {
    reent_ptr->_errno = -result;
    result = -1;
  }
  return result;
}

apos_mode_t _umask_r(struct _reent* reent_ptr, apos_mode_t cmask) {
  apos_mode_t result = _do_umask(cmask);
  if (result < 0) {
    reent_ptr->_errno = -result;
    result = -1;
  }
  return result;
}

apos_pid_t _setsid_r(struct _reent* reent_ptr) {
  apos_pid_t result = _do_setsid();
  if (result < 0) {
    reent_ptr->_errno = -result;
    result = -1;
  }
  return result;
}

apos_pid_t _getsid_r(struct _reent* reent_ptr, apos_pid_t pid) {
  apos_pid_t result = _do_getsid(pid);
  if (result < 0) {
    reent_ptr->_errno = -result;
    result = -1;
  }
  return result;
}

apos_pid_t _tcgetpgrp_r(struct _reent* reent_ptr, int fd) {
  apos_pid_t result = _do_tcgetpgrp(fd);
  if (result < 0) {
    reent_ptr->_errno = -result;
    result = -1;
  }
  return result;
}

int _tcsetpgrp_r(struct _reent* reent_ptr, int fd, apos_pid_t pgid) {
  int result = _do_tcsetpgrp(fd, pgid);
  if (result < 0) {
    reent_ptr->_errno = -result;
    result = -1;
  }
  return result;
}

apos_pid_t _tcgetsid_r(struct _reent* reent_ptr, int fd) {
  apos_pid_t result = _do_tcgetsid(fd);
  if (result < 0) {
    reent_ptr->_errno = -result;
    result = -1;
  }
  return result;
}

int _tcdrain_r(struct _reent* reent_ptr, int fd) {
  int result = _do_tcdrain(fd);
  if (result < 0) {
    reent_ptr->_errno = -result;
    result = -1;
  }
  return result;
}

int _tcflush_r(struct _reent* reent_ptr, int fd, int action) {
  int result = _do_tcflush(fd, action);
  if (result < 0) {
    reent_ptr->_errno = -result;
    result = -1;
  }
  return result;
}

int _tcgetattr_r(struct _reent* reent_ptr, int fd, struct ktermios* t) {
  int result = _do_tcgetattr(fd, t);
  if (result < 0) {
    reent_ptr->_errno = -result;
    result = -1;
  }
  return result;
}

int _tcsetattr_r(struct _reent* reent_ptr, int fd, int optional_actions,
                 const struct ktermios* t) {
  int result = _do_tcsetattr(fd, optional_actions, t);
  if (result < 0) {
    reent_ptr->_errno = -result;
    result = -1;
  }
  return result;
}

int _ftruncate_r(struct _reent* reent_ptr, int fd, apos_off_t length) {
  int result = _do_ftruncate(fd, length);
  if (result < 0) {
    reent_ptr->_errno = -result;
    result = -1;
  }
  return result;
}

int _truncate_r(struct _reent* reent_ptr, const char* path, apos_off_t length) {
  int result = _do_truncate(path, length);
  if (result < 0) {
    reent_ptr->_errno = -result;
    result = -1;
  }
  return result;
}

int _poll_r(struct _reent* reent_ptr, struct apos_pollfd* fds, apos_nfds_t nfds,
            int timeout) {
  int result = _do_poll(fds, nfds, timeout);
  if (result < 0) {
    reent_ptr->_errno = -result;
    result = -1;
  }
  return result;
}

int _getrlimit_r(struct _reent* reent_ptr, int resource,
                 struct apos_rlimit* lim) {
  int result = _do_getrlimit(resource, lim);
  if (result < 0) {
    reent_ptr->_errno = -result;
    result = -1;
  }
  return result;
}

int _setrlimit_r(struct _reent* reent_ptr, int resource,
                 const struct apos_rlimit* lim) {
  int result = _do_setrlimit(resource, lim);
  if (result < 0) {
    reent_ptr->_errno = -result;
    result = -1;
  }
  return result;
}

int _socket_r(struct _reent* reent_ptr, int domain, int type, int protocol) {
  int result = _do_socket(domain, type, protocol);
  if (result < 0) {
    reent_ptr->_errno = -result;
    result = -1;
  }
  return result;
}

int _shutdown_r(struct _reent* reent_ptr, int socket, int how) {
  int result = _do_shutdown(socket, how);
  if (result < 0) {
    reent_ptr->_errno = -result;
    result = -1;
  }
  return result;
}

int _bind_r(struct _reent* reent_ptr, int socket, const struct sockaddr* addr,
            socklen_t addr_len) {
  int result = _do_bind(socket, addr, addr_len);
  if (result < 0) {
    reent_ptr->_errno = -result;
    result = -1;
  }
  return result;
}

int _listen_r(struct _reent* reent_ptr, int socket, int backlog) {
  int result = _do_listen(socket, backlog);
  if (result < 0) {
    reent_ptr->_errno = -result;
    result = -1;
  }
  return result;
}

int _accept_r(struct _reent* reent_ptr, int socket, struct sockaddr* addr,
              socklen_t* addr_len) {
  int result = _do_accept(socket, addr, addr_len);
  if (result < 0) {
    reent_ptr->_errno = -result;
    result = -1;
  }
  return result;
}

int _connect_r(struct _reent* reent_ptr, int socket,
               const struct sockaddr* addr, socklen_t addr_len) {
  int result = _do_connect(socket, addr, addr_len);
  if (result < 0) {
    reent_ptr->_errno = -result;
    result = -1;
  }
  return result;
}

ssize_t _recv_r(struct _reent* reent_ptr, int socket, void* buf, size_t len,
                int flags) {
  ssize_t result = _do_recv(socket, buf, len, flags);
  if (result < 0) {
    reent_ptr->_errno = -result;
    result = -1;
  }
  return result;
}

ssize_t _recvfrom_r(struct _reent* reent_ptr, int socket, void* buf, size_t len,
                    int flags, struct sockaddr* address,
                    socklen_t* address_len) {
  ssize_t result = _do_recvfrom(socket, buf, len, flags, address, address_len);
  if (result < 0) {
    reent_ptr->_errno = -result;
    result = -1;
  }
  return result;
}

ssize_t _send_r(struct _reent* reent_ptr, int socket, const void* buf,
                size_t len, int flags) {
  ssize_t result = _do_send(socket, buf, len, flags);
  if (result < 0) {
    reent_ptr->_errno = -result;
    result = -1;
  }
  return result;
}

ssize_t _sendto_r(struct _reent* reent_ptr, int socket, const void* buf,
                  size_t len, int flags, const struct sockaddr* dest_addr,
                  socklen_t dest_len) {
  ssize_t result = _do_sendto(socket, buf, len, flags, dest_addr, dest_len);
  if (result < 0) {
    reent_ptr->_errno = -result;
    result = -1;
  }
  return result;
}

int _apos_klog_r(struct _reent* reent_ptr, const char* msg) {
  int result = _do_apos_klog(msg);
  return result;
}

int _apos_run_ktest_r(struct _reent* reent_ptr, const char* name) {
  int result = _do_apos_run_ktest(name);
  if (result < 0) {
    reent_ptr->_errno = -result;
    result = -1;
  }
  return result;
}

int _apos_run_ktests_r(struct _reent* reent_ptr, const apos_ktest_t* tests,
                       size_t num) {
  int result = _do_apos_run_ktests(tests, num);
  if (result < 0) {
    reent_ptr->_errno = -result;
    result = -1;
  }
  return result;
}

int _apos_thread_create_r(struct _reent* reent_ptr, apos_uthread_id_t* id,
                          void* stack, void* entry) {
  int result = _do_apos_thread_create(id, stack, entry);
  if (result < 0) {
    reent_ptr->_errno = -result;
    result = -1;
  }
  return result;
}

int _apos_thread_exit_r(struct _reent* reent_ptr) {
  int result = _do_apos_thread_exit();
  return result;
}

int _sigwait_r(struct _reent* reent_ptr, const ksigset_t* sigmask, int* sig) {
  int result = _do_sigwait(sigmask, sig);
  if (result < 0) {
    reent_ptr->_errno = -result;
    result = -1;
  }
  return result;
}

int _apos_thread_kill_r(struct _reent* reent_ptr, const apos_uthread_id_t* id,
                        int sig) {
  int result = _do_apos_thread_kill(id, sig);
  if (result < 0) {
    reent_ptr->_errno = -result;
    result = -1;
  }
  return result;
}

int _apos_thread_self_r(struct _reent* reent_ptr, apos_uthread_id_t* id) {
  int result = _do_apos_thread_self(id);
  if (result < 0) {
    reent_ptr->_errno = -result;
    result = -1;
  }
  return result;
}

int _futex_ts_r(struct _reent* reent_ptr, uint32_t* uaddr, int op, uint32_t val,
                const struct apos_timespec* timespec, uint32_t* uaddr2,
                uint32_t val3) {
  int result = _do_futex_ts(uaddr, op, val, timespec, uaddr2, val3);
  if (result < 0) {
    reent_ptr->_errno = -result;
    result = -1;
  }
  return result;
}

int _mount_r(struct _reent* reent_ptr, const char* source,
             const char* mount_path, const char* type, unsigned long flags,
             const void* data, size_t data_len) {
  int result = _do_mount(source, mount_path, type, flags, data, data_len);
  if (result < 0) {
    reent_ptr->_errno = -result;
    result = -1;
  }
  return result;
}

int _unmount_r(struct _reent* reent_ptr, const char* mount_path,
               unsigned long flags) {
  int result = _do_unmount(mount_path, flags);
  if (result < 0) {
    reent_ptr->_errno = -result;
    result = -1;
  }
  return result;
}

int _getsockopt_r(struct _reent* reent_ptr, int socket, int level, int option,
                  void* val, socklen_t* val_len) {
  int result = _do_getsockopt(socket, level, option, val, val_len);
  if (result < 0) {
    reent_ptr->_errno = -result;
    result = -1;
  }
  return result;
}

int _setsockopt_r(struct _reent* reent_ptr, int socket, int level, int option,
                  const void* val, socklen_t val_len) {
  int result = _do_setsockopt(socket, level, option, val, val_len);
  if (result < 0) {
    reent_ptr->_errno = -result;
    result = -1;
  }
  return result;
}

int _getsockname_r(struct _reent* reent_ptr, int socket,
                   struct sockaddr* address, socklen_t* len) {
  int result = _do_getsockname(socket, address, len);
  if (result < 0) {
    reent_ptr->_errno = -result;
    result = -1;
  }
  return result;
}

int _getpeername_r(struct _reent* reent_ptr, int socket,
                   struct sockaddr* address, socklen_t* len) {
  int result = _do_getpeername(socket, address, len);
  if (result < 0) {
    reent_ptr->_errno = -result;
    result = -1;
  }
  return result;
}

#include <apos/mmap.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>

__attribute__((noreturn)) void _exit(int status) {
  _do_exit(status);
  // Should never get here.  Loop to make the compiler happy.
  while (1) {
  }
}

// We need a custom wrapper to return char* rather than error int.
char* _getcwd_r(struct _reent* reent_ptr, char* buf, size_t size) {
  if (!buf) {
    // TODO(aoates): use VFS_MAX_PATH_LENGTH.
    const int kMaxSize = 1000;  // Guess the max size.
    buf = malloc(kMaxSize);
    size = kMaxSize;
  }
  int result = _do_getcwd(buf, size);
  if (result < 0) {
    reent_ptr->_errno = -result;
    return NULL;
  }
  return buf;
}

char* getcwd(char* buf, size_t size) { return _getcwd_r(_REENT, buf, size); }

void* _mmap_r(struct _reent* reent_ptr, void* addr, size_t len, int prot,
              int flags, int fd, off_t offset) {
  int result = _do_mmap(&addr, len, prot, flags, fd, offset);
  if (result) {
    reent_ptr->_errno = -result;
    return MAP_FAILED;
  }
  return addr;
}

void* mmap(void* addr, size_t len, int prot, int flags, int fd, off_t offset) {
  return _mmap_r(_REENT, addr, len, prot, flags, fd, offset);
}

unsigned alarm(unsigned seconds) { return alarm_ms(seconds * 1000); }

unsigned int sleep(unsigned int seconds) { return sleep_ms(seconds * 1000); }

// Manual stub to convert from int[2] to int* and mollify GCC's
// array-parameter diagnostic.
int pipe(int fildes[2]) { return _pipe_r(_REENT, fildes); }

int open(const char* path, int oflag, ...) {
  mode_t mode = 0;
  if (oflag & O_CREAT) {
    va_list args;
    va_start(args, oflag);
    mode = va_arg(args, mode_t);
    va_end(args);
  }
  return _open_r(_REENT, path, oflag, mode);
}

int fcntl(int fd, int cmd, ...) {
  // Note: this is technically undefined behavior, since the caller could be
  // passing a valid cmd/type pair that we don't know about (and isn't an int).
  // But for now, assume the third argument is always an int.mode_t mode = 0;
  va_list args;
  va_start(args, cmd);
  int arg = va_arg(args, int);
  va_end(args);
  return _fcntl_r(_REENT, fd, cmd, arg);
}
long syscall_test(long arg1, long arg2, long arg3, long arg4, long arg5,
                  long arg6) {
  return _syscall_test_r(_REENT, arg1, arg2, arg3, arg4, arg5, arg6);
}

int close(int fd) { return _close_r(_REENT, fd); }

int dup(int fd) { return _dup_r(_REENT, fd); }

int dup2(int fd1, int fd2) { return _dup2_r(_REENT, fd1, fd2); }

int mkdir(const char* path, apos_mode_t mode) {
  return _mkdir_r(_REENT, path, mode);
}

int mknod(const char* path, apos_mode_t mode, apos_dev_t dev) {
  return _mknod_r(_REENT, path, mode, dev);
}

int rmdir(const char* path) { return _rmdir_r(_REENT, path); }

int link(const char* path1, const char* path2) {
  return _link_r(_REENT, path1, path2);
}

int unlink(const char* path) { return _unlink_r(_REENT, path); }

ssize_t read(int fd, void* buf, size_t count) {
  return _read_r(_REENT, fd, buf, count);
}

ssize_t write(int fd, const void* buf, size_t count) {
  return _write_r(_REENT, fd, buf, count);
}

int getdents(int fd, kdirent_t* buf, int count) {
  return _getdents_r(_REENT, fd, buf, count);
}

int stat(const char* path, apos_stat_t* stat) {
  return _stat_r(_REENT, path, stat);
}

int lstat(const char* path, apos_stat_t* stat) {
  return _lstat_r(_REENT, path, stat);
}

int fstat(int fd, apos_stat_t* stat) { return _fstat_r(_REENT, fd, stat); }

apos_off_t lseek(int fd, apos_off_t offset, int whence) {
  return _lseek_r(_REENT, fd, offset, whence);
}

int chdir(const char* path) { return _chdir_r(_REENT, path); }

int access(const char* path, int amode) {
  return _access_r(_REENT, path, amode);
}

int chown(const char* path, apos_uid_t owner, apos_gid_t group) {
  return _chown_r(_REENT, path, owner, group);
}

int fchown(int fd, apos_uid_t owner, apos_gid_t group) {
  return _fchown_r(_REENT, fd, owner, group);
}

int lchown(const char* path, apos_uid_t owner, apos_gid_t group) {
  return _lchown_r(_REENT, path, owner, group);
}

int chmod(const char* path, apos_mode_t mode) {
  return _chmod_r(_REENT, path, mode);
}

int fchmod(int fd, apos_mode_t mode) { return _fchmod_r(_REENT, fd, mode); }

apos_pid_t fork(void) { return _fork_r(_REENT); }

apos_pid_t vfork(void) { return _vfork_r(_REENT); }

apos_pid_t wait(int* exit_status) { return _wait_r(_REENT, exit_status); }

apos_pid_t waitpid(apos_pid_t child, int* exit_status, int options) {
  return _waitpid_r(_REENT, child, exit_status, options);
}

apos_pid_t getpid(void) { return _getpid_r(_REENT); }

apos_pid_t getppid(void) { return _getppid_r(_REENT); }

int kill(apos_pid_t pid, int sig) { return _kill_r(_REENT, pid, sig); }

int sigaction(int signum, const struct ksigaction* act,
              struct ksigaction* oldact) {
  return _sigaction_r(_REENT, signum, act, oldact);
}

int sigprocmask(int how, const ksigset_t* set, ksigset_t* oset) {
  return _sigprocmask_r(_REENT, how, set, oset);
}

int sigpending(ksigset_t* oset) { return _sigpending_r(_REENT, oset); }

int sigsuspend(const ksigset_t* sigmask) {
  return _sigsuspend_r(_REENT, sigmask);
}

unsigned int alarm_ms(unsigned int seconds) {
  return _alarm_ms_r(_REENT, seconds);
}

int setuid(apos_uid_t uid) { return _setuid_r(_REENT, uid); }

int setgid(apos_gid_t gid) { return _setgid_r(_REENT, gid); }

apos_uid_t getuid(void) { return _getuid_r(_REENT); }

apos_gid_t getgid(void) { return _getgid_r(_REENT); }

int seteuid(apos_uid_t uid) { return _seteuid_r(_REENT, uid); }

int setegid(apos_gid_t gid) { return _setegid_r(_REENT, gid); }

apos_uid_t geteuid(void) { return _geteuid_r(_REENT); }

apos_gid_t getegid(void) { return _getegid_r(_REENT); }

int setreuid(apos_uid_t ruid, apos_uid_t euid) {
  return _setreuid_r(_REENT, ruid, euid);
}

int setregid(apos_gid_t rgid, apos_gid_t egid) {
  return _setregid_r(_REENT, rgid, egid);
}

apos_pid_t getpgid(apos_pid_t pid) { return _getpgid_r(_REENT, pid); }

int setpgid(apos_pid_t pid, apos_pid_t pgid) {
  return _setpgid_r(_REENT, pid, pgid);
}

int munmap(void* addr, size_t length) {
  return _munmap_r(_REENT, addr, length);
}

int symlink(const char* path1, const char* path2) {
  return _symlink_r(_REENT, path1, path2);
}

int readlink(const char* path, char* buf, size_t bufsize) {
  return _readlink_r(_REENT, path, buf, bufsize);
}

int sleep_ms(int milliseconds) { return _sleep_ms_r(_REENT, milliseconds); }

int apos_get_time(struct apos_tm* t) { return _apos_get_time_r(_REENT, t); }

int apos_get_timespec(struct apos_timespec* t) {
  return _apos_get_timespec_r(_REENT, t);
}

apos_mode_t umask(apos_mode_t cmask) { return _umask_r(_REENT, cmask); }

apos_pid_t setsid(void) { return _setsid_r(_REENT); }

apos_pid_t getsid(apos_pid_t pid) { return _getsid_r(_REENT, pid); }

apos_pid_t tcgetpgrp(int fd) { return _tcgetpgrp_r(_REENT, fd); }

int tcsetpgrp(int fd, apos_pid_t pgid) {
  return _tcsetpgrp_r(_REENT, fd, pgid);
}

apos_pid_t tcgetsid(int fd) { return _tcgetsid_r(_REENT, fd); }

int tcdrain(int fd) { return _tcdrain_r(_REENT, fd); }

int tcflush(int fd, int action) { return _tcflush_r(_REENT, fd, action); }

int tcgetattr(int fd, struct ktermios* t) {
  return _tcgetattr_r(_REENT, fd, t);
}

int tcsetattr(int fd, int optional_actions, const struct ktermios* t) {
  return _tcsetattr_r(_REENT, fd, optional_actions, t);
}

int ftruncate(int fd, apos_off_t length) {
  return _ftruncate_r(_REENT, fd, length);
}

int truncate(const char* path, apos_off_t length) {
  return _truncate_r(_REENT, path, length);
}

int poll(struct apos_pollfd* fds, apos_nfds_t nfds, int timeout) {
  return _poll_r(_REENT, fds, nfds, timeout);
}

int getrlimit(int resource, struct apos_rlimit* lim) {
  return _getrlimit_r(_REENT, resource, lim);
}

int setrlimit(int resource, const struct apos_rlimit* lim) {
  return _setrlimit_r(_REENT, resource, lim);
}

int socket(int domain, int type, int protocol) {
  return _socket_r(_REENT, domain, type, protocol);
}

int shutdown(int socket, int how) { return _shutdown_r(_REENT, socket, how); }

int bind(int socket, const struct sockaddr* addr, socklen_t addr_len) {
  return _bind_r(_REENT, socket, addr, addr_len);
}

int listen(int socket, int backlog) {
  return _listen_r(_REENT, socket, backlog);
}

int accept(int socket, struct sockaddr* addr, socklen_t* addr_len) {
  return _accept_r(_REENT, socket, addr, addr_len);
}

int connect(int socket, const struct sockaddr* addr, socklen_t addr_len) {
  return _connect_r(_REENT, socket, addr, addr_len);
}

ssize_t recv(int socket, void* buf, size_t len, int flags) {
  return _recv_r(_REENT, socket, buf, len, flags);
}

ssize_t recvfrom(int socket, void* buf, size_t len, int flags,
                 struct sockaddr* address, socklen_t* address_len) {
  return _recvfrom_r(_REENT, socket, buf, len, flags, address, address_len);
}

ssize_t send(int socket, const void* buf, size_t len, int flags) {
  return _send_r(_REENT, socket, buf, len, flags);
}

ssize_t sendto(int socket, const void* buf, size_t len, int flags,
               const struct sockaddr* dest_addr, socklen_t dest_len) {
  return _sendto_r(_REENT, socket, buf, len, flags, dest_addr, dest_len);
}

int apos_klog(const char* msg) { return _apos_klog_r(_REENT, msg); }

int apos_run_ktest(const char* name) { return _apos_run_ktest_r(_REENT, name); }

int apos_run_ktests(const apos_ktest_t* tests, size_t num) {
  return _apos_run_ktests_r(_REENT, tests, num);
}

int apos_thread_create(apos_uthread_id_t* id, void* stack, void* entry) {
  return _apos_thread_create_r(_REENT, id, stack, entry);
}

int apos_thread_exit(void) { return _apos_thread_exit_r(_REENT); }

int sigwait(const ksigset_t* sigmask, int* sig) {
  return _sigwait_r(_REENT, sigmask, sig);
}

int apos_thread_kill(const apos_uthread_id_t* id, int sig) {
  return _apos_thread_kill_r(_REENT, id, sig);
}

int apos_thread_self(apos_uthread_id_t* id) {
  return _apos_thread_self_r(_REENT, id);
}

int futex_ts(uint32_t* uaddr, int op, uint32_t val,
             const struct apos_timespec* timespec, uint32_t* uaddr2,
             uint32_t val3) {
  return _futex_ts_r(_REENT, uaddr, op, val, timespec, uaddr2, val3);
}

int mount(const char* source, const char* mount_path, const char* type,
          unsigned long flags, const void* data, size_t data_len) {
  return _mount_r(_REENT, source, mount_path, type, flags, data, data_len);
}

int unmount(const char* mount_path, unsigned long flags) {
  return _unmount_r(_REENT, mount_path, flags);
}

int getsockopt(int socket, int level, int option, void* val,
               socklen_t* val_len) {
  return _getsockopt_r(_REENT, socket, level, option, val, val_len);
}

int setsockopt(int socket, int level, int option, const void* val,
               socklen_t val_len) {
  return _setsockopt_r(_REENT, socket, level, option, val, val_len);
}

int getsockname(int socket, struct sockaddr* address, socklen_t* len) {
  return _getsockname_r(_REENT, socket, address, len);
}

int getpeername(int socket, struct sockaddr* address, socklen_t* len) {
  return _getpeername_r(_REENT, socket, address, len);
}
