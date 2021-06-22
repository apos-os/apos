// Copyright 2021 Andrew Oates.  All Rights Reserved.
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

#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "os/common/apos_klog.h"

#define LOGIN_PATH "/bin/login"

int main(int argc, char** argv) {
  if (argc != 2) {
    apos_klogf("getty invoked with wrong number of args\n");
    exit(1);
  }

  const char* tty = argv[1];
  pid_t me = setsid();
  if (me < 0) {
    apos_klogf("getty unable to setsid()\n");
    exit(1);
  }

  // Open the TTY; this should set the controlling terminal of our session.
  int fd = open(tty, O_RDWR | O_NONBLOCK);
  if (fd < 0) {
    apos_klogf("getty unable to open TTY '%s'\n", tty);
    exit(1);
  }

  // TODO(aoates): set O_NONBLOCK on the above FD rather than reopening.
  close(fd);
  fd = open(tty, O_RDWR);
  if (fd < 0) {
    apos_klogf("getty unable to open TTY '%s'\n", tty);
    exit(1);
  }

  // Set up stdin/stdout/stderr.
  dup2(fd, 0);
  dup2(fd, 1);
  dup2(fd, 2);
  if (fd > 2) close(fd);

  // TODO(aoates): set up standard TTY configuration.
  // TODO(aoates): confirm or force CTTY.

  // Ignore job control signals; this sets the default behavior for shells
  // (which can un-ignore if they choose), and prevents a SIGTTOU in the
  // tcsetpgrp() call.
  // TODO(aoates): SIG_ERR isn't defined in APOS headers --- it should be, and
  // confirmed to match the newlib definitions.
  if (signal(SIGTTIN, SIG_IGN) == SIG_ERR ||
      signal(SIGTTOU, SIG_IGN) == SIG_ERR ||
      signal(SIGTSTP, SIG_IGN) == SIG_ERR) {
    perror("getty unable to set signal handlers");
    apos_klogf("getty unable to set signal handlers\n");
    exit(1);
  }

  // Make us the foreground process group for the TTY.
  if (tcsetpgrp(0, me) < 0) {
    perror("Unable to tcsetpgrp()");
    apos_klogf("getty unable to tcsetpgrp()\n");
    exit(1);
  }

  char* login_argv[] = {LOGIN_PATH, NULL};
  char* login_envp[] = {NULL};
  execve(LOGIN_PATH, login_argv, login_envp);
  perror("Unable to exec " LOGIN_PATH);
  apos_klogf("getty unable to exec " LOGIN_PATH "\n");
  exit(1);
}
