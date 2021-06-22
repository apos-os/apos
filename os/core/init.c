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

// Very basic init daemon.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/errno.h>
#include <sys/wait.h>
#include <unistd.h>

#include "os/common/apos_klog.h"

#define GETTY_PATH "/bin/getty"
#define TTY0 "/dev/tty0"

static pid_t do_getty(const char* tty) {
  pid_t child = fork();
  if (child == 0) {
    char* ttybuf = malloc(strlen(tty) + 1);
    strcpy(ttybuf, tty);
    char* new_argv[] = {GETTY_PATH, ttybuf, NULL};
    char* new_envp[] = {NULL};
    execve(GETTY_PATH, new_argv, new_envp);
    apos_klogf("Unable to exec " GETTY_PATH "\n");
    exit(1);
  }
  return child;
}

int main(int argc, char** argv) {
  while (1) {
    pid_t child = do_getty(TTY0);

    pid_t wait_result;
    do {
      wait_result = wait(NULL);
      if (wait_result < 0) {
        char err[50];
        strerror_r(errno, err, 50);
        apos_klogf("init unable to wait: %s\n", err);
        exit(1);
      }
    } while (wait_result != child);
  }
  return 0;
}
