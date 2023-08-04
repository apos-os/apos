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

// Declarations of all syscalls as they're named in userspace.
#ifndef APOO_USER_SYSCALLS_DECLS_H
#define APOO_USER_SYSCALLS_DECLS_H

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

// Declare the userspace functions.
long syscall_test(long arg1, long arg2, long arg3, long arg4, long arg5,
                  long arg6);
int dup(int fd);
int dup2(int fd1, int fd2);
int mkdir(const char* path, apos_mode_t mode);
int mknod(const char* path, apos_mode_t mode, apos_dev_t dev);
int rmdir(const char* path);
int rename(const char* path1, const char* path2);
int getdents(int fd, kdirent_t* buf, int count);
int lstat(const char* path, apos_stat_t* stat);
int chdir(const char* path);
int access(const char* path, int amode);
int chown(const char* path, apos_uid_t owner, apos_gid_t group);
int fchown(int fd, apos_uid_t owner, apos_gid_t group);
int lchown(const char* path, apos_uid_t owner, apos_gid_t group);
int chmod(const char* path, apos_mode_t mode);
int fchmod(int fd, apos_mode_t mode);
apos_pid_t vfork(void);
apos_pid_t waitpid(apos_pid_t child, int* exit_status, int options);
apos_pid_t getppid(void);
int sigaction(int signum, const struct ksigaction* act,
              struct ksigaction* oldact);
int sigprocmask(int how, const ksigset_t* set, ksigset_t* oset);
int sigpending(ksigset_t* oset);
int sigsuspend(const ksigset_t* sigmask);
unsigned int alarm_ms(unsigned int seconds);
int setuid(apos_uid_t uid);
int setgid(apos_gid_t gid);
apos_uid_t getuid(void);
apos_gid_t getgid(void);
int seteuid(apos_uid_t uid);
int setegid(apos_gid_t gid);
apos_uid_t geteuid(void);
apos_gid_t getegid(void);
int setreuid(apos_uid_t ruid, apos_uid_t euid);
int setregid(apos_gid_t rgid, apos_gid_t egid);
apos_pid_t getpgid(apos_pid_t pid);
int setpgid(apos_pid_t pid, apos_pid_t pgid);
int munmap(void* addr, size_t length);
int symlink(const char* path1, const char* path2);
int readlink(const char* path, char* buf, size_t bufsize);
int sleep_ms(int seconds);
int apos_get_time(struct apos_tm* t);
apos_mode_t umask(apos_mode_t cmask);
apos_pid_t setsid(void);
apos_pid_t getsid(apos_pid_t pid);
apos_pid_t tcgetpgrp(int fd);
int tcsetpgrp(int fd, apos_pid_t pgid);
apos_pid_t tcgetsid(int fd);
int tcdrain(int fd);
int tcflush(int fd, int action);
int tcgetattr(int fd, struct ktermios* t);
int tcsetattr(int fd, int optional_actions, const struct ktermios* t);
int ftruncate(int fd, apos_off_t length);
int truncate(const char* path, apos_off_t length);
int poll(struct apos_pollfd* fds, apos_nfds_t nfds, int timeout);
int getrlimit(int resource, struct apos_rlimit* lim);
int setrlimit(int resource, const struct apos_rlimit* lim);
int socket(int domain, int type, int protocol);
int shutdown(int socket, int how);
int bind(int socket, const struct sockaddr* addr, socklen_t addr_len);
int listen(int socket, int backlog);
int accept(int socket, struct sockaddr* addr, socklen_t* addr_len);
int connect(int socket, const struct sockaddr* addr, socklen_t addr_len);
ssize_t recv(int socket, void* buf, size_t len, int flags);
ssize_t recvfrom(int socket, void* buf, size_t len, int flags,
                 struct sockaddr* address, socklen_t* address_len);
ssize_t send(int socket, const void* buf, size_t len, int flags);
ssize_t sendto(int socket, const void* buf, size_t len, int flags,
               const struct sockaddr* dest_addr, socklen_t dest_len);
int apos_klog(const char* msg);
int apos_run_ktest(const char* name);
int apos_thread_create(apos_uthread_id_t* id, void* stack, void* entry);
int apos_thread_exit(void);
int sigwait(const ksigset_t* sigmask, int* sig);
int apos_thread_kill(const apos_uthread_id_t* id, int sig);
int apos_thread_self(apos_uthread_id_t* id);
int futex_ts(uint32_t* uaddr, int op, uint32_t val,
             const struct apos_timespec* timespec, uint32_t* uaddr2,
             uint32_t val3);
int mount(const char* source, const char* mount_path, const char* type,
          unsigned long flags, const void* data, size_t data_len);
int unmount(const char* mount_path, unsigned long flags);

#endif
