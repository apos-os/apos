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

#include "arch/syscall/context.h"
#include "common/errno.h"
#include "common/kassert.h"
#include "common/klog.h"
#include "common/time.h"
#include "dev/termios.h"
#include "memory/mmap.h"
#include "net/socket/socket.h"
#include "proc/alarm.h"
#include "proc/futex.h"
#include "proc/group.h"
#include "proc/limit.h"
#include "proc/process.h"
#include "proc/session.h"
#include "proc/signal/signal.h"
#include "proc/sleep.h"
#include "proc/tcgroup.h"
#include "proc/umask.h"
#include "proc/user.h"
#include "proc/user_prepare.h"
#include "proc/user_thread.h"
#include "proc/wait.h"
#include "syscall/execve_wrapper.h"
#include "syscall/fork.h"
#include "syscall/syscall_dispatch.h"
#include "syscall/test.h"
#include "syscall/wrappers.h"
#include "syscall/wrappers32.h"
#include "test/kernel_tests.h"
#include "user/include/apos/syscalls.h"
#include "vfs/mount.h"
#include "vfs/pipe.h"
#include "vfs/poll.h"
#include "vfs/vfs.h"

// Assert that all argument types are valid.
_Static_assert(sizeof(long) <= sizeof(long),
               "invalid argument type: long (sizeof(long) > sizeof(long))");
_Static_assert(
    sizeof(const char*) <= sizeof(long),
    "invalid argument type: const char* (sizeof(const char*) > sizeof(long))");
_Static_assert(sizeof(int) <= sizeof(long),
               "invalid argument type: int (sizeof(int) > sizeof(long))");
_Static_assert(
    sizeof(apos_mode_t) <= sizeof(long),
    "invalid argument type: apos_mode_t (sizeof(apos_mode_t) > sizeof(long))");
_Static_assert(
    sizeof(apos_dev_t) <= sizeof(long),
    "invalid argument type: apos_dev_t (sizeof(apos_dev_t) > sizeof(long))");
_Static_assert(sizeof(void*) <= sizeof(long),
               "invalid argument type: void* (sizeof(void*) > sizeof(long))");
_Static_assert(sizeof(size_t) <= sizeof(long),
               "invalid argument type: size_t (sizeof(size_t) > sizeof(long))");
_Static_assert(
    sizeof(const void*) <= sizeof(long),
    "invalid argument type: const void* (sizeof(const void*) > sizeof(long))");
_Static_assert(sizeof(kdirent_32_t*) <= sizeof(long),
               "invalid argument type: kdirent_32_t* (sizeof(kdirent_32_t*) > "
               "sizeof(long))");
_Static_assert(
    sizeof(kdirent_t*) <= sizeof(long),
    "invalid argument type: kdirent_t* (sizeof(kdirent_t*) > sizeof(long))");
_Static_assert(sizeof(char*) <= sizeof(long),
               "invalid argument type: char* (sizeof(char*) > sizeof(long))");
_Static_assert(sizeof(apos_stat_32_t*) <= sizeof(long),
               "invalid argument type: apos_stat_32_t* "
               "(sizeof(apos_stat_32_t*) > sizeof(long))");
_Static_assert(sizeof(apos_stat_t*) <= sizeof(long),
               "invalid argument type: apos_stat_t* (sizeof(apos_stat_t*) > "
               "sizeof(long))");
_Static_assert(
    sizeof(apos_off_t) <= sizeof(long),
    "invalid argument type: apos_off_t (sizeof(apos_off_t) > sizeof(long))");
_Static_assert(
    sizeof(apos_uid_t) <= sizeof(long),
    "invalid argument type: apos_uid_t (sizeof(apos_uid_t) > sizeof(long))");
_Static_assert(
    sizeof(apos_gid_t) <= sizeof(long),
    "invalid argument type: apos_gid_t (sizeof(apos_gid_t) > sizeof(long))");
_Static_assert(sizeof(int*) <= sizeof(long),
               "invalid argument type: int* (sizeof(int*) > sizeof(long))");
_Static_assert(
    sizeof(apos_pid_t) <= sizeof(long),
    "invalid argument type: apos_pid_t (sizeof(apos_pid_t) > sizeof(long))");
_Static_assert(sizeof(char* const*) <= sizeof(long),
               "invalid argument type: char* const* (sizeof(char* const*) > "
               "sizeof(long))");
_Static_assert(sizeof(const struct ksigaction_32*) <= sizeof(long),
               "invalid argument type: const struct ksigaction_32* "
               "(sizeof(const struct ksigaction_32*) > sizeof(long))");
_Static_assert(sizeof(struct ksigaction_32*) <= sizeof(long),
               "invalid argument type: struct ksigaction_32* (sizeof(struct "
               "ksigaction_32*) > sizeof(long))");
_Static_assert(sizeof(const struct ksigaction*) <= sizeof(long),
               "invalid argument type: const struct ksigaction* (sizeof(const "
               "struct ksigaction*) > sizeof(long))");
_Static_assert(sizeof(struct ksigaction*) <= sizeof(long),
               "invalid argument type: struct ksigaction* (sizeof(struct "
               "ksigaction*) > sizeof(long))");
_Static_assert(sizeof(const ksigset_t*) <= sizeof(long),
               "invalid argument type: const ksigset_t* (sizeof(const "
               "ksigset_t*) > sizeof(long))");
_Static_assert(
    sizeof(ksigset_t*) <= sizeof(long),
    "invalid argument type: ksigset_t* (sizeof(ksigset_t*) > sizeof(long))");
_Static_assert(sizeof(const user_context_t*) <= sizeof(long),
               "invalid argument type: const user_context_t* (sizeof(const "
               "user_context_t*) > sizeof(long))");
_Static_assert(sizeof(const syscall_context_t*) <= sizeof(long),
               "invalid argument type: const syscall_context_t* (sizeof(const "
               "syscall_context_t*) > sizeof(long))");
_Static_assert(sizeof(unsigned int) <= sizeof(long),
               "invalid argument type: unsigned int (sizeof(unsigned int) > "
               "sizeof(long))");
_Static_assert(sizeof(struct apos_tm*) <= sizeof(long),
               "invalid argument type: struct apos_tm* (sizeof(struct "
               "apos_tm*) > sizeof(long))");
_Static_assert(sizeof(struct ktermios*) <= sizeof(long),
               "invalid argument type: struct ktermios* (sizeof(struct "
               "ktermios*) > sizeof(long))");
_Static_assert(sizeof(const struct ktermios*) <= sizeof(long),
               "invalid argument type: const struct ktermios* (sizeof(const "
               "struct ktermios*) > sizeof(long))");
_Static_assert(sizeof(struct apos_pollfd*) <= sizeof(long),
               "invalid argument type: struct apos_pollfd* (sizeof(struct "
               "apos_pollfd*) > sizeof(long))");
_Static_assert(
    sizeof(apos_nfds_t) <= sizeof(long),
    "invalid argument type: apos_nfds_t (sizeof(apos_nfds_t) > sizeof(long))");
_Static_assert(sizeof(struct apos_rlimit_32*) <= sizeof(long),
               "invalid argument type: struct apos_rlimit_32* (sizeof(struct "
               "apos_rlimit_32*) > sizeof(long))");
_Static_assert(sizeof(struct apos_rlimit*) <= sizeof(long),
               "invalid argument type: struct apos_rlimit* (sizeof(struct "
               "apos_rlimit*) > sizeof(long))");
_Static_assert(sizeof(const struct apos_rlimit_32*) <= sizeof(long),
               "invalid argument type: const struct apos_rlimit_32* "
               "(sizeof(const struct apos_rlimit_32*) > sizeof(long))");
_Static_assert(sizeof(const struct apos_rlimit*) <= sizeof(long),
               "invalid argument type: const struct apos_rlimit* (sizeof(const "
               "struct apos_rlimit*) > sizeof(long))");
_Static_assert(sizeof(const struct sockaddr*) <= sizeof(long),
               "invalid argument type: const struct sockaddr* (sizeof(const "
               "struct sockaddr*) > sizeof(long))");
_Static_assert(
    sizeof(socklen_t) <= sizeof(long),
    "invalid argument type: socklen_t (sizeof(socklen_t) > sizeof(long))");
_Static_assert(sizeof(struct sockaddr*) <= sizeof(long),
               "invalid argument type: struct sockaddr* (sizeof(struct "
               "sockaddr*) > sizeof(long))");
_Static_assert(
    sizeof(socklen_t*) <= sizeof(long),
    "invalid argument type: socklen_t* (sizeof(socklen_t*) > sizeof(long))");
_Static_assert(sizeof(apos_uthread_id_t*) <= sizeof(long),
               "invalid argument type: apos_uthread_id_t* "
               "(sizeof(apos_uthread_id_t*) > sizeof(long))");
_Static_assert(sizeof(const apos_uthread_id_t*) <= sizeof(long),
               "invalid argument type: const apos_uthread_id_t* (sizeof(const "
               "apos_uthread_id_t*) > sizeof(long))");
_Static_assert(
    sizeof(uint32_t*) <= sizeof(long),
    "invalid argument type: uint32_t* (sizeof(uint32_t*) > sizeof(long))");
_Static_assert(
    sizeof(uint32_t) <= sizeof(long),
    "invalid argument type: uint32_t (sizeof(uint32_t) > sizeof(long))");
_Static_assert(sizeof(const struct apos_timespec*) <= sizeof(long),
               "invalid argument type: const struct apos_timespec* "
               "(sizeof(const struct apos_timespec*) > sizeof(long))");
_Static_assert(sizeof(unsigned long) <= sizeof(long),
               "invalid argument type: unsigned long (sizeof(unsigned long) > "
               "sizeof(long))");

// Forward declare DMZ functions.
long SYSCALL_DMZ_syscall_test(long arg1, long arg2, long arg3, long arg4,
                              long arg5, long arg6);
int SYSCALL_DMZ_open(const char* path, int flags, apos_mode_t mode);
int SYSCALL_DMZ_close(int fd);
int SYSCALL_DMZ_dup(int fd);
int SYSCALL_DMZ_dup2(int fd1, int fd2);
int SYSCALL_DMZ_mkdir(const char* path, apos_mode_t mode);
int SYSCALL_DMZ_mknod(const char* path, apos_mode_t mode, apos_dev_t dev);
int SYSCALL_DMZ_rmdir(const char* path);
int SYSCALL_DMZ_link(const char* path1, const char* path2);
int SYSCALL_DMZ_rename(const char* path1, const char* path2);
int SYSCALL_DMZ_unlink(const char* path);
int SYSCALL_DMZ_read(int fd, void* buf, size_t count);
int SYSCALL_DMZ_write(int fd, const void* buf, size_t count);
int SYSCALL_DMZ_getdents_32(int fd, kdirent_32_t* buf, int count);
int SYSCALL_DMZ_getdents(int fd, kdirent_t* buf, int count);
int SYSCALL_DMZ_getcwd(char* path_out, size_t size);
int SYSCALL_DMZ_stat_32(const char* path, apos_stat_32_t* stat);
int SYSCALL_DMZ_stat(const char* path, apos_stat_t* stat);
int SYSCALL_DMZ_lstat_32(const char* path, apos_stat_32_t* stat);
int SYSCALL_DMZ_lstat(const char* path, apos_stat_t* stat);
int SYSCALL_DMZ_fstat_32(int fd, apos_stat_32_t* stat);
int SYSCALL_DMZ_fstat(int fd, apos_stat_t* stat);
apos_off_t SYSCALL_DMZ_lseek(int fd, apos_off_t offset, int whence);
int SYSCALL_DMZ_chdir(const char* path);
int SYSCALL_DMZ_access(const char* path, int amode);
int SYSCALL_DMZ_chown(const char* path, apos_uid_t owner, apos_gid_t group);
int SYSCALL_DMZ_fchown(int fd, apos_uid_t owner, apos_gid_t group);
int SYSCALL_DMZ_lchown(const char* path, apos_uid_t owner, apos_gid_t group);
int SYSCALL_DMZ_chmod(const char* path, apos_mode_t mode);
int SYSCALL_DMZ_fchmod(int fd, apos_mode_t mode);
apos_pid_t SYSCALL_DMZ_fork(void);
apos_pid_t SYSCALL_DMZ_vfork(void);
int SYSCALL_DMZ_exit(int status);
apos_pid_t SYSCALL_DMZ_wait(int* exit_status);
apos_pid_t SYSCALL_DMZ_waitpid(apos_pid_t child, int* exit_status, int options);
int SYSCALL_DMZ_execve_32(const char* path, char* const* argv,
                          char* const* envp);
int SYSCALL_DMZ_execve(const char* path, char* const* argv, char* const* envp);
apos_pid_t SYSCALL_DMZ_getpid(void);
apos_pid_t SYSCALL_DMZ_getppid(void);
int SYSCALL_DMZ_isatty(int fd);
int SYSCALL_DMZ_kill(apos_pid_t pid, int sig);
int SYSCALL_DMZ_sigaction_32(int signum, const struct ksigaction_32* act,
                             struct ksigaction_32* oldact);
int SYSCALL_DMZ_sigaction(int signum, const struct ksigaction* act,
                          struct ksigaction* oldact);
int SYSCALL_DMZ_sigprocmask(int how, const ksigset_t* set, ksigset_t* oset);
int SYSCALL_DMZ_sigpending(ksigset_t* oset);
int SYSCALL_DMZ_sigsuspend(const ksigset_t* sigmask);
int SYSCALL_DMZ_sigreturn(const ksigset_t* old_mask,
                          const user_context_t* context,
                          const syscall_context_t* syscall_context);
unsigned int SYSCALL_DMZ_alarm_ms(unsigned int seconds);
int SYSCALL_DMZ_setuid(apos_uid_t uid);
int SYSCALL_DMZ_setgid(apos_gid_t gid);
apos_uid_t SYSCALL_DMZ_getuid(void);
apos_gid_t SYSCALL_DMZ_getgid(void);
int SYSCALL_DMZ_seteuid(apos_uid_t uid);
int SYSCALL_DMZ_setegid(apos_gid_t gid);
apos_uid_t SYSCALL_DMZ_geteuid(void);
apos_gid_t SYSCALL_DMZ_getegid(void);
int SYSCALL_DMZ_setreuid(apos_uid_t ruid, apos_uid_t euid);
int SYSCALL_DMZ_setregid(apos_gid_t rgid, apos_gid_t egid);
apos_pid_t SYSCALL_DMZ_getpgid(apos_pid_t pid);
int SYSCALL_DMZ_setpgid(apos_pid_t pid, apos_pid_t pgid);
int SYSCALL_DMZ_mmap_32(void* addr_inout, size_t length, int prot, int flags,
                        int fd, apos_off_t offset);
int SYSCALL_DMZ_mmap(void* addr_inout, size_t length, int prot, int flags,
                     int fd, apos_off_t offset);
int SYSCALL_DMZ_munmap(void* addr, size_t length);
int SYSCALL_DMZ_symlink(const char* path1, const char* path2);
int SYSCALL_DMZ_readlink(const char* path, char* buf, size_t bufsize);
int SYSCALL_DMZ_sleep_ms(int seconds);
int SYSCALL_DMZ_apos_get_time(struct apos_tm* t);
int SYSCALL_DMZ_pipe(int* fildes);
apos_mode_t SYSCALL_DMZ_umask(apos_mode_t cmask);
apos_pid_t SYSCALL_DMZ_setsid(void);
apos_pid_t SYSCALL_DMZ_getsid(apos_pid_t pid);
apos_pid_t SYSCALL_DMZ_tcgetpgrp(int fd);
int SYSCALL_DMZ_tcsetpgrp(int fd, apos_pid_t pgid);
apos_pid_t SYSCALL_DMZ_tcgetsid(int fd);
int SYSCALL_DMZ_tcdrain(int fd);
int SYSCALL_DMZ_tcflush(int fd, int action);
int SYSCALL_DMZ_tcgetattr(int fd, struct ktermios* t);
int SYSCALL_DMZ_tcsetattr(int fd, int optional_actions,
                          const struct ktermios* t);
int SYSCALL_DMZ_ftruncate(int fd, apos_off_t length);
int SYSCALL_DMZ_truncate(const char* path, apos_off_t length);
int SYSCALL_DMZ_poll(struct apos_pollfd* fds, apos_nfds_t nfds, int timeout);
int SYSCALL_DMZ_getrlimit_32(int resource, struct apos_rlimit_32* lim);
int SYSCALL_DMZ_getrlimit(int resource, struct apos_rlimit* lim);
int SYSCALL_DMZ_setrlimit_32(int resource, const struct apos_rlimit_32* lim);
int SYSCALL_DMZ_setrlimit(int resource, const struct apos_rlimit* lim);
int SYSCALL_DMZ_socket(int domain, int type, int protocol);
int SYSCALL_DMZ_shutdown(int socket, int how);
int SYSCALL_DMZ_bind(int socket, const struct sockaddr* addr,
                     socklen_t addr_len);
int SYSCALL_DMZ_listen(int socket, int backlog);
int SYSCALL_DMZ_accept(int socket, struct sockaddr* addr, socklen_t* addr_len);
int SYSCALL_DMZ_connect(int socket, const struct sockaddr* addr,
                        socklen_t addr_len);
ssize_t SYSCALL_DMZ_recv(int socket, void* buf, size_t len, int flags);
ssize_t SYSCALL_DMZ_recvfrom(int socket, void* buf, size_t len, int flags,
                             struct sockaddr* address, socklen_t* address_len);
ssize_t SYSCALL_DMZ_send(int socket, const void* buf, size_t len, int flags);
ssize_t SYSCALL_DMZ_sendto(int socket, const void* buf, size_t len, int flags,
                           const struct sockaddr* dest_addr,
                           socklen_t dest_len);
int SYSCALL_DMZ_apos_klog(const char* msg);
int SYSCALL_DMZ_apos_run_ktest(const char* name);
int SYSCALL_DMZ_apos_thread_create(apos_uthread_id_t* id, void* stack,
                                   void* entry);
int SYSCALL_DMZ_apos_thread_exit(void);
int SYSCALL_DMZ_sigwait(const ksigset_t* sigmask, int* sig);
int SYSCALL_DMZ_apos_thread_kill(const apos_uthread_id_t* id, int sig);
int SYSCALL_DMZ_apos_thread_self(apos_uthread_id_t* id);
int SYSCALL_DMZ_futex_ts(uint32_t* uaddr, int op, uint32_t val,
                         const struct apos_timespec* timespec, uint32_t* uaddr2,
                         uint32_t val3);
int SYSCALL_DMZ_mount(const char* source, const char* mount_path,
                      const char* type, unsigned long flags, const void* data,
                      size_t data_len);
int SYSCALL_DMZ_unmount(const char* mount_path, unsigned long flags);

static long do_syscall_dispatch(long syscall_number, long arg1, long arg2,
                                long arg3, long arg4, long arg5, long arg6) {
  switch (syscall_number) {
    case SYS_SYSCALL_TEST:
      return SYSCALL_DMZ_syscall_test((long)arg1, (long)arg2, (long)arg3,
                                      (long)arg4, (long)arg5, (long)arg6);

    case SYS_OPEN:
      return SYSCALL_DMZ_open((const char*)arg1, (int)arg2, (apos_mode_t)arg3);

    case SYS_CLOSE:
      return SYSCALL_DMZ_close((int)arg1);

    case SYS_DUP:
      return SYSCALL_DMZ_dup((int)arg1);

    case SYS_DUP2:
      return SYSCALL_DMZ_dup2((int)arg1, (int)arg2);

    case SYS_MKDIR:
      return SYSCALL_DMZ_mkdir((const char*)arg1, (apos_mode_t)arg2);

    case SYS_MKNOD:
      return SYSCALL_DMZ_mknod((const char*)arg1, (apos_mode_t)arg2,
                               (apos_dev_t)arg3);

    case SYS_RMDIR:
      return SYSCALL_DMZ_rmdir((const char*)arg1);

    case SYS_LINK:
      return SYSCALL_DMZ_link((const char*)arg1, (const char*)arg2);

    case SYS_RENAME:
      return SYSCALL_DMZ_rename((const char*)arg1, (const char*)arg2);

    case SYS_UNLINK:
      return SYSCALL_DMZ_unlink((const char*)arg1);

    case SYS_READ:
      return SYSCALL_DMZ_read((int)arg1, (void*)arg2, (size_t)arg3);

    case SYS_WRITE:
      return SYSCALL_DMZ_write((int)arg1, (const void*)arg2, (size_t)arg3);

    case SYS_GETDENTS:
      if (ARCH_IS_64_BIT && bin_32bit(proc_current()->user_arch)) {
        return SYSCALL_DMZ_getdents_32((int)arg1, (kdirent_32_t*)arg2,
                                       (int)arg3);
      } else {
        return SYSCALL_DMZ_getdents((int)arg1, (kdirent_t*)arg2, (int)arg3);
      }

    case SYS_GETCWD:
      return SYSCALL_DMZ_getcwd((char*)arg1, (size_t)arg2);

    case SYS_STAT:
      if (ARCH_IS_64_BIT && bin_32bit(proc_current()->user_arch)) {
        return SYSCALL_DMZ_stat_32((const char*)arg1, (apos_stat_32_t*)arg2);
      } else {
        return SYSCALL_DMZ_stat((const char*)arg1, (apos_stat_t*)arg2);
      }

    case SYS_LSTAT:
      if (ARCH_IS_64_BIT && bin_32bit(proc_current()->user_arch)) {
        return SYSCALL_DMZ_lstat_32((const char*)arg1, (apos_stat_32_t*)arg2);
      } else {
        return SYSCALL_DMZ_lstat((const char*)arg1, (apos_stat_t*)arg2);
      }

    case SYS_FSTAT:
      if (ARCH_IS_64_BIT && bin_32bit(proc_current()->user_arch)) {
        return SYSCALL_DMZ_fstat_32((int)arg1, (apos_stat_32_t*)arg2);
      } else {
        return SYSCALL_DMZ_fstat((int)arg1, (apos_stat_t*)arg2);
      }

    case SYS_LSEEK:
      return SYSCALL_DMZ_lseek((int)arg1, (apos_off_t)arg2, (int)arg3);

    case SYS_CHDIR:
      return SYSCALL_DMZ_chdir((const char*)arg1);

    case SYS_ACCESS:
      return SYSCALL_DMZ_access((const char*)arg1, (int)arg2);

    case SYS_CHOWN:
      return SYSCALL_DMZ_chown((const char*)arg1, (apos_uid_t)arg2,
                               (apos_gid_t)arg3);

    case SYS_FCHOWN:
      return SYSCALL_DMZ_fchown((int)arg1, (apos_uid_t)arg2, (apos_gid_t)arg3);

    case SYS_LCHOWN:
      return SYSCALL_DMZ_lchown((const char*)arg1, (apos_uid_t)arg2,
                                (apos_gid_t)arg3);

    case SYS_CHMOD:
      return SYSCALL_DMZ_chmod((const char*)arg1, (apos_mode_t)arg2);

    case SYS_FCHMOD:
      return SYSCALL_DMZ_fchmod((int)arg1, (apos_mode_t)arg2);

    case SYS_FORK:
      return SYSCALL_DMZ_fork();

    case SYS_VFORK:
      return SYSCALL_DMZ_vfork();

    case SYS_EXIT:
      kthread_current_thread()->syscall_ctx.flags &= ~SCCTX_RESTARTABLE;
      return SYSCALL_DMZ_exit((int)arg1);

    case SYS_WAIT:
      return SYSCALL_DMZ_wait((int*)arg1);

    case SYS_WAITPID:
      return SYSCALL_DMZ_waitpid((apos_pid_t)arg1, (int*)arg2, (int)arg3);

    case SYS_EXECVE:
      if (ARCH_IS_64_BIT && bin_32bit(proc_current()->user_arch)) {
        return SYSCALL_DMZ_execve_32((const char*)arg1, (char* const*)arg2,
                                     (char* const*)arg3);
      } else {
        return SYSCALL_DMZ_execve((const char*)arg1, (char* const*)arg2,
                                  (char* const*)arg3);
      }

    case SYS_GETPID:
      kthread_current_thread()->syscall_ctx.flags &= ~SCCTX_RESTARTABLE;
      return SYSCALL_DMZ_getpid();

    case SYS_GETPPID:
      kthread_current_thread()->syscall_ctx.flags &= ~SCCTX_RESTARTABLE;
      return SYSCALL_DMZ_getppid();

    case SYS_ISATTY:
      return SYSCALL_DMZ_isatty((int)arg1);

    case SYS_KILL:
      return SYSCALL_DMZ_kill((apos_pid_t)arg1, (int)arg2);

    case SYS_SIGACTION:
      if (ARCH_IS_64_BIT && bin_32bit(proc_current()->user_arch)) {
        return SYSCALL_DMZ_sigaction_32((int)arg1,
                                        (const struct ksigaction_32*)arg2,
                                        (struct ksigaction_32*)arg3);
      } else {
        return SYSCALL_DMZ_sigaction((int)arg1, (const struct ksigaction*)arg2,
                                     (struct ksigaction*)arg3);
      }

    case SYS_SIGPROCMASK:
      return SYSCALL_DMZ_sigprocmask((int)arg1, (const ksigset_t*)arg2,
                                     (ksigset_t*)arg3);

    case SYS_SIGPENDING:
      return SYSCALL_DMZ_sigpending((ksigset_t*)arg1);

    case SYS_SIGSUSPEND:
      return SYSCALL_DMZ_sigsuspend((const ksigset_t*)arg1);

    case SYS_SIGRETURN:
      return SYSCALL_DMZ_sigreturn((const ksigset_t*)arg1,
                                   (const user_context_t*)arg2,
                                   (const syscall_context_t*)arg3);

    case SYS_ALARM_MS:
      kthread_current_thread()->syscall_ctx.flags &= ~SCCTX_RESTARTABLE;
      return SYSCALL_DMZ_alarm_ms((unsigned int)arg1);

    case SYS_SETUID:
      return SYSCALL_DMZ_setuid((apos_uid_t)arg1);

    case SYS_SETGID:
      return SYSCALL_DMZ_setgid((apos_gid_t)arg1);

    case SYS_GETUID:
      kthread_current_thread()->syscall_ctx.flags &= ~SCCTX_RESTARTABLE;
      return SYSCALL_DMZ_getuid();

    case SYS_GETGID:
      kthread_current_thread()->syscall_ctx.flags &= ~SCCTX_RESTARTABLE;
      return SYSCALL_DMZ_getgid();

    case SYS_SETEUID:
      return SYSCALL_DMZ_seteuid((apos_uid_t)arg1);

    case SYS_SETEGID:
      return SYSCALL_DMZ_setegid((apos_gid_t)arg1);

    case SYS_GETEUID:
      kthread_current_thread()->syscall_ctx.flags &= ~SCCTX_RESTARTABLE;
      return SYSCALL_DMZ_geteuid();

    case SYS_GETEGID:
      kthread_current_thread()->syscall_ctx.flags &= ~SCCTX_RESTARTABLE;
      return SYSCALL_DMZ_getegid();

    case SYS_SETREUID:
      return SYSCALL_DMZ_setreuid((apos_uid_t)arg1, (apos_uid_t)arg2);

    case SYS_SETREGID:
      return SYSCALL_DMZ_setregid((apos_gid_t)arg1, (apos_gid_t)arg2);

    case SYS_GETPGID:
      return SYSCALL_DMZ_getpgid((apos_pid_t)arg1);

    case SYS_SETPGID:
      return SYSCALL_DMZ_setpgid((apos_pid_t)arg1, (apos_pid_t)arg2);

    case SYS_MMAP:
      if (ARCH_IS_64_BIT && bin_32bit(proc_current()->user_arch)) {
        return SYSCALL_DMZ_mmap_32((void*)arg1, (size_t)arg2, (int)arg3,
                                   (int)arg4, (int)arg5, (apos_off_t)arg6);
      } else {
        return SYSCALL_DMZ_mmap((void*)arg1, (size_t)arg2, (int)arg3, (int)arg4,
                                (int)arg5, (apos_off_t)arg6);
      }

    case SYS_MUNMAP:
      return SYSCALL_DMZ_munmap((void*)arg1, (size_t)arg2);

    case SYS_SYMLINK:
      return SYSCALL_DMZ_symlink((const char*)arg1, (const char*)arg2);

    case SYS_READLINK:
      return SYSCALL_DMZ_readlink((const char*)arg1, (char*)arg2, (size_t)arg3);

    case SYS_SLEEP_MS:
      return SYSCALL_DMZ_sleep_ms((int)arg1);

    case SYS_APOS_GET_TIME:
      return SYSCALL_DMZ_apos_get_time((struct apos_tm*)arg1);

    case SYS_PIPE:
      return SYSCALL_DMZ_pipe((int*)arg1);

    case SYS_UMASK:
      return SYSCALL_DMZ_umask((apos_mode_t)arg1);

    case SYS_SETSID:
      return SYSCALL_DMZ_setsid();

    case SYS_GETSID:
      return SYSCALL_DMZ_getsid((apos_pid_t)arg1);

    case SYS_TCGETPGRP:
      return SYSCALL_DMZ_tcgetpgrp((int)arg1);

    case SYS_TCSETPGRP:
      return SYSCALL_DMZ_tcsetpgrp((int)arg1, (apos_pid_t)arg2);

    case SYS_TCGETSID:
      return SYSCALL_DMZ_tcgetsid((int)arg1);

    case SYS_TCDRAIN:
      return SYSCALL_DMZ_tcdrain((int)arg1);

    case SYS_TCFLUSH:
      return SYSCALL_DMZ_tcflush((int)arg1, (int)arg2);

    case SYS_TCGETATTR:
      return SYSCALL_DMZ_tcgetattr((int)arg1, (struct ktermios*)arg2);

    case SYS_TCSETATTR:
      return SYSCALL_DMZ_tcsetattr((int)arg1, (int)arg2,
                                   (const struct ktermios*)arg3);

    case SYS_FTRUNCATE:
      return SYSCALL_DMZ_ftruncate((int)arg1, (apos_off_t)arg2);

    case SYS_TRUNCATE:
      return SYSCALL_DMZ_truncate((const char*)arg1, (apos_off_t)arg2);

    case SYS_POLL:
      return SYSCALL_DMZ_poll((struct apos_pollfd*)arg1, (apos_nfds_t)arg2,
                              (int)arg3);

    case SYS_GETRLIMIT:
      if (ARCH_IS_64_BIT && bin_32bit(proc_current()->user_arch)) {
        return SYSCALL_DMZ_getrlimit_32((int)arg1,
                                        (struct apos_rlimit_32*)arg2);
      } else {
        return SYSCALL_DMZ_getrlimit((int)arg1, (struct apos_rlimit*)arg2);
      }

    case SYS_SETRLIMIT:
      if (ARCH_IS_64_BIT && bin_32bit(proc_current()->user_arch)) {
        return SYSCALL_DMZ_setrlimit_32((int)arg1,
                                        (const struct apos_rlimit_32*)arg2);
      } else {
        return SYSCALL_DMZ_setrlimit((int)arg1,
                                     (const struct apos_rlimit*)arg2);
      }

    case SYS_SOCKET:
      return SYSCALL_DMZ_socket((int)arg1, (int)arg2, (int)arg3);

    case SYS_SHUTDOWN:
      return SYSCALL_DMZ_shutdown((int)arg1, (int)arg2);

    case SYS_BIND:
      return SYSCALL_DMZ_bind((int)arg1, (const struct sockaddr*)arg2,
                              (socklen_t)arg3);

    case SYS_LISTEN:
      return SYSCALL_DMZ_listen((int)arg1, (int)arg2);

    case SYS_ACCEPT:
      return SYSCALL_DMZ_accept((int)arg1, (struct sockaddr*)arg2,
                                (socklen_t*)arg3);

    case SYS_CONNECT:
      return SYSCALL_DMZ_connect((int)arg1, (const struct sockaddr*)arg2,
                                 (socklen_t)arg3);

    case SYS_RECV:
      return SYSCALL_DMZ_recv((int)arg1, (void*)arg2, (size_t)arg3, (int)arg4);

    case SYS_RECVFROM:
      return SYSCALL_DMZ_recvfrom((int)arg1, (void*)arg2, (size_t)arg3,
                                  (int)arg4, (struct sockaddr*)arg5,
                                  (socklen_t*)arg6);

    case SYS_SEND:
      return SYSCALL_DMZ_send((int)arg1, (const void*)arg2, (size_t)arg3,
                              (int)arg4);

    case SYS_SENDTO:
      return SYSCALL_DMZ_sendto((int)arg1, (const void*)arg2, (size_t)arg3,
                                (int)arg4, (const struct sockaddr*)arg5,
                                (socklen_t)arg6);

    case SYS_APOS_KLOG:
      kthread_current_thread()->syscall_ctx.flags &= ~SCCTX_RESTARTABLE;
      return SYSCALL_DMZ_apos_klog((const char*)arg1);

    case SYS_APOS_RUN_KTEST:
      return SYSCALL_DMZ_apos_run_ktest((const char*)arg1);

    case SYS_APOS_THREAD_CREATE:
      return SYSCALL_DMZ_apos_thread_create((apos_uthread_id_t*)arg1,
                                            (void*)arg2, (void*)arg3);

    case SYS_APOS_THREAD_EXIT:
      kthread_current_thread()->syscall_ctx.flags &= ~SCCTX_RESTARTABLE;
      return SYSCALL_DMZ_apos_thread_exit();

    case SYS_SIGWAIT:
      return SYSCALL_DMZ_sigwait((const ksigset_t*)arg1, (int*)arg2);

    case SYS_APOS_THREAD_KILL:
      return SYSCALL_DMZ_apos_thread_kill((const apos_uthread_id_t*)arg1,
                                          (int)arg2);

    case SYS_APOS_THREAD_SELF:
      return SYSCALL_DMZ_apos_thread_self((apos_uthread_id_t*)arg1);

    case SYS_FUTEX_TS:
      return SYSCALL_DMZ_futex_ts((uint32_t*)arg1, (int)arg2, (uint32_t)arg3,
                                  (const struct apos_timespec*)arg4,
                                  (uint32_t*)arg5, (uint32_t)arg6);

    case SYS_MOUNT:
      return SYSCALL_DMZ_mount((const char*)arg1, (const char*)arg2,
                               (const char*)arg3, (unsigned long)arg4,
                               (const void*)arg5, (size_t)arg6);

    case SYS_UNMOUNT:
      return SYSCALL_DMZ_unmount((const char*)arg1, (unsigned long)arg2);

    default:
      proc_kill(proc_current()->id, SIGSYS);
      return -ENOTSUP;
  }
}

long syscall_dispatch(long syscall_number, long arg1, long arg2, long arg3,
                      long arg4, long arg5, long arg6) {
  KASSERT_DBG(proc_current()->user_arch != BIN_NONE);
  kthread_current_thread()->syscall_ctx.flags = SCCTX_RESTARTABLE;

  klogfm(KL_SYSCALL, DEBUG, "SYSCALL %ld (%#lx, %#lx, %#lx, %#lx, %#lx, %#lx)",
         syscall_number, (unsigned long)arg1, (unsigned long)arg2,
         (unsigned long)arg3, (unsigned long)arg4, (unsigned long)arg5,
         (unsigned long)arg6);

  const long result =
      do_syscall_dispatch(syscall_number, arg1, arg2, arg3, arg4, arg5, arg6);

  klogfm(KL_SYSCALL, DEBUG, " --> %ld (%#lx)\n", result, (unsigned long)result);
  return result;
}
