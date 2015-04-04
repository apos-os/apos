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
#include <sys/stat.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>


// Declare the userspace functions.
long syscall_test(long arg1, long arg2, long arg3, long arg4, long arg5, long arg6);
int dup(int fd);
int dup2(int fd1, int fd2);
int mkdir(const char* path, mode_t mode);
int mknod(const char* path, mode_t mode, apos_dev_t dev);
int rmdir(const char* path);
int rename(const char* path1, const char* path2);
int getdents(int fd, dirent_t* buf, int count);
int lstat(const char* path, apos_stat_t* stat);
int chdir(const char* path);
int access(const char* path, int amode);
int chown(const char* path, uid_t owner, gid_t group);
int fchown(int fd, uid_t owner, gid_t group);
int lchown(const char* path, uid_t owner, gid_t group);
int chmod(const char* path, mode_t mode);
int fchmod(int fd, mode_t mode);
pid_t vfork(void);
pid_t waitpid(pid_t child, int* exit_status, int options);
pid_t getppid(void);
int sigaction(int signum, const struct sigaction* act, struct sigaction* oldact);
int sigprocmask(int how, const sigset_t* set, sigset_t* oset);
int sigpending(sigset_t* oset);
int sigsuspend(const sigset_t* sigmask);
unsigned int alarm_ms(unsigned int seconds);
int setuid(uid_t uid);
int setgid(gid_t gid);
uid_t getuid(void);
gid_t getgid(void);
int seteuid(uid_t uid);
int setegid(gid_t gid);
uid_t geteuid(void);
gid_t getegid(void);
int setreuid(uid_t ruid, uid_t euid);
int setregid(gid_t rgid, gid_t egid);
pid_t getpgid(pid_t pid);
int setpgid(pid_t pid, pid_t pgid);
int munmap(void* addr, size_t length);
int symlink(const char* path1, const char* path2);
int readlink(const char* path, char* buf, size_t bufsize);
int sleep_ms(unsigned int seconds);
int apos_get_time(struct apos_tm* t);
int pipe(int* fildes);
mode_t umask(mode_t cmask);
pid_t setsid(void);
pid_t getsid(pid_t pid);
pid_t tcgetpgrp(int fd);
int tcsetpgrp(int fd, pid_t pgid);
pid_t tcgetsid(int fd);
int tcdrain(int fd);
int tcflush(int fd, int action);
int tcgetattr(int fd, struct termios* t);
int tcsetattr(int fd, int optional_actions, const struct termios* t);
int ftruncate(int fd, off_t length);
int truncate(const char* path, off_t length);
int poll(struct pollfd* fds, nfds_t nfds, int timeout);

#endif
