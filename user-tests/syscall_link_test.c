// Copyright 2026 Andrew Oates.  All Rights Reserved.
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

#include <apos/syscall_decls.h>
#include <sys/time.h>   // For utimes, gettimeofday
#include <sys/times.h>  // For times
#include <unistd.h>     // For sbrk, getentropy

// This file simply calls every syscall we know must be defined in the standard
// userspace environment.  This verifies that all functions are linked properly
// into libc, without having to test compiling multiple different userspace
// binaries that use different subsets.

// First, the syscalls defined built-in by APOS.
static void direct_syscalls(void) {
  syscall_test(0, 0, 0, 0, 0, 0);
  open(NULL, 0, 0);
  close(0);
  dup(0);
  dup2(0, 0);
  mkdir(NULL, 0);
  mknod(NULL, 0, 0);
  rmdir(NULL);
  link(NULL, NULL);
  rename(NULL, NULL);
  unlink(NULL);
  read(0, NULL, 0);
  write(0, NULL, 0);
  getdents(0, NULL, 0);
  getcwd(NULL, 0);
  stat(NULL, NULL);
  lstat(NULL, NULL);
  fstat(0, NULL);
  lseek(0, 0, 0);
  chdir(NULL);
  access(NULL, 0);
  chown(NULL, 0, 0);
  fchown(0, 0, 0);
  lchown(NULL, 0, 0);
  chmod(NULL, 0);
  fchmod(0, 0);
  fcntl(0, 0, 0);
  fork();
  vfork();
  exit(0);
  wait(NULL);
  waitpid(0, NULL, 0);
  execve(NULL, NULL, NULL);
  getpid();
  getppid();
  isatty(0);
  kill(0, 0);
  sigaction(0, NULL, NULL);
  sigprocmask(0, NULL, NULL);
  sigpending(NULL);
  sigsuspend(NULL);
  alarm_ms(0);
  setuid(0);
  setgid(0);
  getuid();
  getgid();
  seteuid(0);
  setegid(0);
  geteuid();
  getegid();
  setreuid(0, 0);
  setregid(0, 0);
  getpgid(0);
  setpgid(0, 0);
  mmap(NULL, 0, 0, 0, 0, 0);
  munmap(NULL, 0);
  symlink(NULL, NULL);
  readlink(NULL, NULL, 0);
  sleep_ms(0);
  apos_get_time(NULL);
  apos_get_timespec(NULL);
  pipe(NULL);
  umask(0);
  setsid();
  getsid(0);
  tcgetpgrp(0);
  tcsetpgrp(0, 0);
  tcgetsid(0);
  tcdrain(0);
  tcflush(0, 0);
  tcgetattr(0, NULL);
  tcsetattr(0, 0, NULL);
  ftruncate(0, 0);
  truncate(NULL, 0);
  poll(NULL, 0, 0);
  getrlimit(0, NULL);
  setrlimit(0, NULL);
  socket(0, 0, 0);
  shutdown(0, 0);
  bind(0, NULL, 0);
  listen(0, 0);
  accept(0, NULL, NULL);
  connect(0, NULL, 0);
  recv(0, NULL, 0, 0);
  recvfrom(0, NULL, 0, 0, NULL, NULL);
  send(0, NULL, 0, 0);
  sendto(0, NULL, 0, 0, NULL, 0);
  apos_klog(NULL);
  apos_run_ktest(NULL);
  apos_run_ktests(NULL, 0);
  apos_thread_create(NULL, NULL, NULL);
  apos_thread_exit();
  sigwait(NULL, NULL);
  apos_thread_kill(NULL, 0);
  apos_thread_self(NULL);
  futex_ts(NULL, 0, 0, NULL, NULL, 0);
  mount(NULL, NULL, NULL, 0, NULL, 0);
  unmount(NULL, 0);
  getsockopt(0, 0, 0, NULL, NULL);
  setsockopt(0, 0, 0, NULL, 0);
  getsockname(0, NULL, NULL);
  getpeername(0, NULL, NULL);
}

// Syscalls implemented in userspace, or libc functions.
static void userspace_functions(void) {
  utimes(0, NULL);
  sbrk(0);
  gettimeofday(NULL, NULL);
  times(NULL);
  getentropy(NULL, 0);
}

int main(void) {
  direct_syscalls();
  userspace_functions();
}
