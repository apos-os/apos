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

#include <fcntl.h>
#include <sys/signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>

#include <apos/sleep.h>
#include <apos/syscall_decls.h>

#include "ktest.h"

static bool create_file(const char* path) {
  int fd = open(path, O_CREAT | O_RDONLY, S_IRWXU);
  if (fd < 0) return false;
  close(fd);
  return true;
}

static bool file_exists(const char* path) {
  int fd = open(path, O_RDONLY);
  if (fd < 0 && errno == ENOENT) {
    return false;
  } else if (fd < 0) {
    perror("open() in file_exists() failed");
    return false;
  }
  close(fd);
  return true;
}

static void exit_status_test(void) {
  KTEST_BEGIN("Exit status macros (normal status)");
  const int statuses[6] = {0, 1, 2, 10, 65, 127};
  for (int i = 0; i < 6; ++i) {
    pid_t child = fork();
    if (child == 0) {
      exit(statuses[i]);
    }
    int status;
    KEXPECT_EQ(child, waitpid(child, &status, 0));
    KEXPECT_NE(0, WIFEXITED(status));
    KEXPECT_EQ(statuses[i], WEXITSTATUS(status));
    KEXPECT_EQ(0, WIFSIGNALED(status));
    KEXPECT_EQ(0, WIFSTOPPED(status));
    KEXPECT_EQ(0, WIFCONTINUED(status));
  }

  KTEST_BEGIN("Exit status macros (terminated with signal)");
  const int term_sigs[3] = {SIGKILL, SIGQUIT, SIGUSR1};
  for (int i = 0; i < 3; ++i) {
    pid_t child = fork();
    if (child == 0) {
      sleep(1);
      exit(0);
    }
    KEXPECT_EQ(0, kill(child, term_sigs[i]));
    int status;
    KEXPECT_EQ(child, wait(&status));

    KEXPECT_EQ(0, WIFEXITED(status));
    KEXPECT_NE(0, WIFSIGNALED(status));
    KEXPECT_EQ(term_sigs[i], WTERMSIG(status));
    KEXPECT_EQ(0, WIFSTOPPED(status));
    KEXPECT_EQ(0, WIFCONTINUED(status));
  }
}

static void stopped_test(void) {
  KTEST_BEGIN("waitpid() with WUNTRACED (exited)");
  pid_t child;
  if ((child = fork()) == 0) {
    exit(1);
  }
  int status;
  KEXPECT_EQ(child, waitpid(-1, &status, WUNTRACED));
  KEXPECT_NE(0, WIFEXITED(status));
  KEXPECT_EQ(1, WEXITSTATUS(status));
  KEXPECT_EQ(0, WIFSIGNALED(status));
  KEXPECT_EQ(0, WIFSTOPPED(status));
  KEXPECT_EQ(0, WIFCONTINUED(status));


  KTEST_BEGIN("waitpid() with WUNTRACED (killed with signal)");
  if ((child = fork()) == 0) {
    kill(getpid(), SIGKILL);
  }
  KEXPECT_EQ(child, waitpid(-1, &status, WUNTRACED));
  KEXPECT_EQ(0, WIFEXITED(status));
  KEXPECT_NE(0, WIFSIGNALED(status));
  KEXPECT_EQ(SIGKILL, WTERMSIG(status));
  KEXPECT_EQ(0, WIFSTOPPED(status));
  KEXPECT_EQ(0, WIFCONTINUED(status));


  KTEST_BEGIN("waitpid() with WUNTRACED (running)");
  if ((child = fork()) == 0) {
    sleep_ms(100);
    create_file("sleep_done");
    exit(1);
  }
  KEXPECT_EQ(child, waitpid(-1, &status, WUNTRACED));
  KEXPECT_EQ(true, file_exists("sleep_done"));
  KEXPECT_EQ(0, unlink("sleep_done"));
  KEXPECT_NE(0, WIFEXITED(status));
  KEXPECT_EQ(0, WIFSIGNALED(status));
  KEXPECT_EQ(0, WIFSTOPPED(status));
  KEXPECT_EQ(0, WIFCONTINUED(status));


  KTEST_BEGIN("waitpid() with WUNTRACED (stopped w/ SIGSTOP)");
  if ((child = fork()) == 0) {
    kill(getpid(), SIGSTOP);
    exit(1);  // Shouldn't get here.
  }
  KEXPECT_EQ(child, waitpid(-1, &status, WUNTRACED));
  KEXPECT_EQ(0, WIFEXITED(status));
  KEXPECT_EQ(0, WIFSIGNALED(status));
  KEXPECT_NE(0, WIFSTOPPED(status));
  KEXPECT_EQ(SIGSTOP, WSTOPSIG(status));
  KEXPECT_EQ(0, WIFCONTINUED(status));
  KEXPECT_EQ(0, kill(child, SIGKILL));
  KEXPECT_EQ(child, wait(NULL));


  KTEST_BEGIN("waitpid() with WUNTRACED (stopped w/ SIGTSTP)");
  if ((child = fork()) == 0) {
    kill(getpid(), SIGTSTP);
    exit(1);  // Shouldn't get here.
  }
  KEXPECT_EQ(child, waitpid(-1, &status, WUNTRACED));
  KEXPECT_EQ(0, WIFEXITED(status));
  KEXPECT_EQ(0, WIFSIGNALED(status));
  KEXPECT_NE(0, WIFSTOPPED(status));
  KEXPECT_EQ(SIGTSTP, WSTOPSIG(status));
  KEXPECT_EQ(0, WIFCONTINUED(status));
  KEXPECT_EQ(0, kill(child, SIGKILL));
  KEXPECT_EQ(child, wait(NULL));


  KTEST_BEGIN("waitpid() with WUNTRACED (NULL status)");
  if ((child = fork()) == 0) {
    kill(getpid(), SIGSTOP);
    exit(1);  // Shouldn't get here.
  }
  KEXPECT_EQ(child, waitpid(-1, NULL, WUNTRACED));
  KEXPECT_EQ(0, kill(child, SIGKILL));
  KEXPECT_EQ(child, wait(NULL));


  KTEST_BEGIN("waitpid() with WUNTRACED (only returns once for stopped)");
  if ((child = fork()) == 0) {
    alarm_ms(100);
    kill(getpid(), SIGSTOP);
    exit(1);
  }
  KEXPECT_EQ(child, waitpid(-1, &status, WUNTRACED));
  KEXPECT_EQ(0, WIFEXITED(status));
  KEXPECT_EQ(0, WIFSIGNALED(status));
  KEXPECT_NE(0, WIFSTOPPED(status));
  KEXPECT_EQ(SIGSTOP, WSTOPSIG(status));
  KEXPECT_EQ(0, WIFCONTINUED(status));

  KEXPECT_EQ(child, waitpid(-1, &status, WUNTRACED));
  // TODO(aoates): verify blocking.
  KEXPECT_EQ(0, WIFEXITED(status));
  KEXPECT_NE(0, WIFSIGNALED(status));
  KEXPECT_EQ(SIGALRM, WTERMSIG(status));
  KEXPECT_EQ(0, WIFSTOPPED(status));
  KEXPECT_EQ(0, WIFCONTINUED(status));


  KTEST_BEGIN("waitpid() with WUNTRACED (resets stopped even if status == NULL)");
  if ((child = fork()) == 0) {
    alarm_ms(100);
    kill(getpid(), SIGSTOP);
    exit(1);
  }
  KEXPECT_EQ(child, waitpid(-1, NULL, WUNTRACED));
  KEXPECT_EQ(child, waitpid(-1, &status, WUNTRACED));
  // TODO(aoates): verify blocking.
  KEXPECT_EQ(0, WIFEXITED(status));
  KEXPECT_NE(0, WIFSIGNALED(status));
  KEXPECT_EQ(SIGALRM, WTERMSIG(status));
  KEXPECT_EQ(0, WIFSTOPPED(status));
  KEXPECT_EQ(0, WIFCONTINUED(status));


  KTEST_BEGIN("waitpid() with WUNTRACED (double stop)");
  if ((child = fork()) == 0) {
    alarm_ms(100);
    kill(getpid(), SIGSTOP);
    exit(1);
  }
  KEXPECT_EQ(child, waitpid(-1, &status, WUNTRACED));
  KEXPECT_NE(0, WIFSTOPPED(status));
  KEXPECT_EQ(0, kill(child, SIGSTOP));

  KEXPECT_EQ(child, waitpid(-1, &status, WUNTRACED));
  KEXPECT_NE(0, WIFSTOPPED(status));

  KEXPECT_EQ(child, waitpid(-1, &status, WUNTRACED));
  // TODO(aoates): verify blocking.
  KEXPECT_EQ(0, WIFEXITED(status));
  KEXPECT_NE(0, WIFSIGNALED(status));
  KEXPECT_EQ(SIGALRM, WTERMSIG(status));
  KEXPECT_EQ(0, WIFSTOPPED(status));
  KEXPECT_EQ(0, WIFCONTINUED(status));
}

static void continued_test(void) {
  KTEST_BEGIN("waitpid() with WCONTINUED (exited)");
  pid_t child;
  if ((child = fork()) == 0) {
    exit(1);
  }
  int status;
  KEXPECT_EQ(child, waitpid(-1, &status, WCONTINUED));
  KEXPECT_NE(0, WIFEXITED(status));
  KEXPECT_EQ(1, WEXITSTATUS(status));
  KEXPECT_EQ(0, WIFSIGNALED(status));
  KEXPECT_EQ(0, WIFSTOPPED(status));
  KEXPECT_EQ(0, WIFCONTINUED(status));


  KTEST_BEGIN("waitpid() with WCONTINUED (killed with signal)");
  if ((child = fork()) == 0) {
    kill(getpid(), SIGKILL);
  }
  KEXPECT_EQ(child, waitpid(-1, &status, WCONTINUED));
  KEXPECT_EQ(0, WIFEXITED(status));
  KEXPECT_NE(0, WIFSIGNALED(status));
  KEXPECT_EQ(SIGKILL, WTERMSIG(status));
  KEXPECT_EQ(0, WIFSTOPPED(status));
  KEXPECT_EQ(0, WIFCONTINUED(status));


  KTEST_BEGIN("waitpid() with WCONTINUED (running)");
  if ((child = fork()) == 0) {
    sleep_ms(100);
    create_file("sleep_done");
    exit(1);
  }
  KEXPECT_EQ(child, waitpid(-1, &status, WCONTINUED));
  KEXPECT_EQ(true, file_exists("sleep_done"));
  KEXPECT_EQ(0, unlink("sleep_done"));
  KEXPECT_NE(0, WIFEXITED(status));
  KEXPECT_EQ(0, WIFSIGNALED(status));
  KEXPECT_EQ(0, WIFSTOPPED(status));
  KEXPECT_EQ(0, WIFCONTINUED(status));


  KTEST_BEGIN("waitpid() with WCONTINUED (stopped w/ SIGSTOP)");
  if ((child = fork()) == 0) {
    alarm_ms(100);
    kill(getpid(), SIGSTOP);
  }
  KEXPECT_EQ(child, waitpid(-1, &status, WCONTINUED));
  KEXPECT_EQ(0, WIFEXITED(status));
  KEXPECT_NE(0, WIFSIGNALED(status));
  KEXPECT_EQ(SIGALRM, WTERMSIG(status));
  KEXPECT_EQ(0, WIFSTOPPED(status));
  KEXPECT_EQ(0, WIFCONTINUED(status));


  KTEST_BEGIN("waitpid() with WCONTINUED (stopped then continued)");
  if ((child = fork()) == 0) {
    kill(getpid(), SIGSTOP);
    sleep(1000);
  }
  KEXPECT_EQ(child, waitpid(-1, &status, WUNTRACED));
  KEXPECT_EQ(0, kill(child, SIGCONT));

  KEXPECT_EQ(child, waitpid(-1, &status, WCONTINUED));
  KEXPECT_EQ(0, WIFEXITED(status));
  KEXPECT_EQ(0, WIFSIGNALED(status));
  KEXPECT_EQ(0, WIFSTOPPED(status));
  KEXPECT_NE(0, WIFCONTINUED(status));
  KEXPECT_EQ(0, kill(child, SIGKILL));
  KEXPECT_EQ(child, wait(NULL));


  KTEST_BEGIN("waitpid() with WCONTINUED (with status == NULL)");
  if ((child = fork()) == 0) {
    kill(getpid(), SIGSTOP);
    sleep(1000);
  }
  KEXPECT_EQ(child, waitpid(-1, NULL, WUNTRACED));
  KEXPECT_EQ(0, kill(child, SIGCONT));
  KEXPECT_EQ(child, waitpid(-1, NULL, WCONTINUED));
  KEXPECT_EQ(0, kill(child, SIGKILL));
  KEXPECT_EQ(child, wait(NULL));


  KTEST_BEGIN("waitpid() with WCONTINUED (doesn't return twice for one continue)");
  if ((child = fork()) == 0) {
    kill(getpid(), SIGSTOP);
    sleep_ms(100);
    exit(0);
  }
  KEXPECT_EQ(child, waitpid(-1, &status, WUNTRACED));
  KEXPECT_EQ(0, kill(child, SIGCONT));

  KEXPECT_EQ(child, waitpid(-1, &status, WCONTINUED));
  KEXPECT_EQ(0, WIFEXITED(status));
  KEXPECT_EQ(0, WIFSIGNALED(status));
  KEXPECT_EQ(0, WIFSTOPPED(status));
  KEXPECT_NE(0, WIFCONTINUED(status));

  KEXPECT_EQ(child, waitpid(-1, &status, WCONTINUED));
  KEXPECT_NE(0, WIFEXITED(status));


  KTEST_BEGIN("waitpid() with WCONTINUED (SIGCONT on running process)");
  if ((child = fork()) == 0) {
    sleep_ms(100);
    exit(0);
  }
  KEXPECT_EQ(0, kill(child, SIGCONT));

  KEXPECT_EQ(child, waitpid(-1, &status, WCONTINUED));
  KEXPECT_EQ(0, WIFEXITED(status));
  KEXPECT_EQ(0, WIFSIGNALED(status));
  KEXPECT_EQ(0, WIFSTOPPED(status));
  KEXPECT_NE(0, WIFCONTINUED(status));

  KEXPECT_EQ(child, waitpid(-1, &status, WCONTINUED));
  KEXPECT_NE(0, WIFEXITED(status));


  KTEST_BEGIN("waitpid() with WCONTINUED (SIGCONT on running process)");
  if ((child = fork()) == 0) {
    sleep_ms(100);
    kill(getpid(), SIGKILL);
  }
  KEXPECT_EQ(0, kill(child, SIGCONT));

  KEXPECT_EQ(child, waitpid(-1, &status, WCONTINUED));
  KEXPECT_EQ(0, WIFEXITED(status));
  KEXPECT_EQ(0, WIFSIGNALED(status));
  KEXPECT_EQ(0, WIFSTOPPED(status));
  KEXPECT_NE(0, WIFCONTINUED(status));
  KEXPECT_EQ(child, wait(NULL));
}

static void no_hang_test(void) {
  KTEST_BEGIN("waitpid(): WNOHANG without children");
  int result = waitpid(-1, NULL, WNOHANG);
  int err = errno;
  KEXPECT_EQ(-1, result);
  KEXPECT_EQ(ECHILD, err);

  KTEST_BEGIN("waitpid(): WNOHANG with stopped child");
  pid_t child;
  if ((child = fork()) == 0) {
    exit(0);
  }
  sleep_ms(100);
  int status;
  KEXPECT_EQ(child, waitpid(-1, &status, WNOHANG));
  KEXPECT_NE(0, WIFEXITED(status));


  KTEST_BEGIN("waitpid(): WNOHANG with running child");
  if ((child = fork()) == 0) {
    sleep_ms(50);
    exit(0);
  }
  KEXPECT_EQ(0, waitpid(-1, &status, WNOHANG));
  KEXPECT_EQ(child, waitpid(-1, &status, 0));
  KEXPECT_NE(0, WIFEXITED(status));


  KTEST_BEGIN("waitpid(): WNOHANG with stopped child");
  if ((child = fork()) == 0) {
    kill(getpid(), SIGSTOP);
    exit(0);
  }
  sleep_ms(10);
  KEXPECT_EQ(0, waitpid(-1, &status, WNOHANG));
  KEXPECT_EQ(0, waitpid(-1, &status, WNOHANG | WCONTINUED));
  KEXPECT_EQ(child, waitpid(-1, &status, WNOHANG | WUNTRACED));
  KEXPECT_NE(0, WIFSTOPPED(status));
  KEXPECT_EQ(0, waitpid(-1, &status, WNOHANG | WUNTRACED));
  KEXPECT_EQ(0, kill(child, SIGKILL));
  KEXPECT_EQ(child, wait(NULL));


  KTEST_BEGIN("waitpid(): WNOHANG with continued child");
  if ((child = fork()) == 0) {
    kill(getpid(), SIGSTOP);
    sleep_ms(100);
    exit(0);
  }
  sleep_ms(10);
  kill(child, SIGCONT);
  sleep_ms(10);
  KEXPECT_EQ(0, waitpid(-1, &status, WNOHANG));
  KEXPECT_EQ(0, waitpid(-1, &status, WNOHANG | WUNTRACED));
  KEXPECT_EQ(child, waitpid(-1, &status, WNOHANG | WCONTINUED));
  KEXPECT_NE(0, WIFCONTINUED(status));
  KEXPECT_EQ(0, waitpid(-1, &status, WNOHANG | WUNTRACED));
  KEXPECT_EQ(child, waitpid(-1, &status, WUNTRACED));
  // TODO(aoates): without the above, the child segfaults.  Why?
}

void wait_test(void) {
  KTEST_SUITE_BEGIN("wait() and waitpid() tests");
  exit_status_test();
  stopped_test();
  continued_test();
  no_hang_test();
}
