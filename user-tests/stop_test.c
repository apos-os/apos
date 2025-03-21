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

#include <assert.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <apos/sleep.h>
#include <apos/syscall_decls.h>

#include "ktest.h"
#include "all_tests.h"
#include "user/include/apos/wait.h"

#define SLEEP_MS 50
#define SLEEP_MS_SMALL 20

static const char* get_proc_state(pid_t pid, char* state_buf) {
  const size_t kBufSize = 1024;
  char buf[kBufSize];
  sprintf(buf, "/proc/%d/status", pid);
  int fd = open(buf, O_RDONLY);
  if (fd < 0) {
    perror("open() failed in get_proc_state()");
    return NULL;
  }

  ssize_t bytes = read(fd, buf, kBufSize);
  if (bytes < 0) {
    perror("read() failed");
    close(fd);
    return NULL;
  }

  close(fd);
  const char* line_start = buf;
  while (line_start) {
    if (sscanf(line_start, "state: %s", state_buf) > 0) {
      return state_buf;
    }
    line_start = strchr(line_start, '\n');
    if (line_start) line_start++;
  }

  return NULL;
}

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

static void file_handler(int sig) {
  create_file("got_signal");
}

// TODO(aoates): put these in a common location.
static sigset_t make_sigset(int signo) {
  sigset_t set;
  sigemptyset(&set);
  sigaddset(&set, signo);
  return set;
}

static void basic_stop_test(void) {
  char state_buf[20];

  KTEST_BEGIN("Basic stop/continue test");
  pid_t child = fork();
  if (child == 0) {
    kill(getpid(), SIGSTOP);
    create_file("child_continued");
    sleep_ms(SLEEP_MS);
    exit(0);
  }

  sleep_ms(SLEEP_MS);
  KEXPECT_STREQ("STOPPED", get_proc_state(child, state_buf));
  KEXPECT_EQ(false, file_exists("child_continued"));
  KEXPECT_EQ(0, kill(child, SIGCONT));
  sleep_ms(SLEEP_MS_SMALL);
  KEXPECT_STREQ("RUNNING", get_proc_state(child, state_buf));
  KEXPECT_EQ(true, file_exists("child_continued"));
  KEXPECT_EQ(0, unlink("child_continued"));

  int status;
  KEXPECT_EQ(child, wait(&status));
  KEXPECT_EQ(0, status);


  KTEST_BEGIN("Stop from parent test");
  child = fork();
  if (child == 0) {
    sleep_ms(SLEEP_MS);
    create_file("child_continued");
    exit(0);
  }

  KEXPECT_STREQ("RUNNING", get_proc_state(child, state_buf));
  KEXPECT_EQ(0, kill(child, SIGSTOP));
  sleep_ms(SLEEP_MS);
  KEXPECT_STREQ("STOPPED", get_proc_state(child, state_buf));
  KEXPECT_EQ(false, file_exists("child_continued"));
  KEXPECT_EQ(0, kill(child, SIGCONT));
  sleep_ms(2 * SLEEP_MS);
  KEXPECT_EQ(true, file_exists("child_continued"));
  KEXPECT_EQ(0, unlink("child_continued"));
  KEXPECT_EQ(child, wait(&status));
  KEXPECT_EQ(0, status);
}

// Helper for cont_masked_test below.  Runs the parent side of the test.
static void cont_masked_test_parent(pid_t child) {
  char state_buf[20];

  sleep_ms(SLEEP_MS);
  KEXPECT_STREQ("STOPPED", get_proc_state(child, state_buf));
  KEXPECT_EQ(false, file_exists("child_continued"));
  KEXPECT_EQ(0, kill(child, SIGCONT));
  sleep_ms(SLEEP_MS_SMALL);
  KEXPECT_STREQ("RUNNING", get_proc_state(child, state_buf));
  KEXPECT_EQ(true, file_exists("child_continued"));
  KEXPECT_EQ(0, unlink("child_continued"));

  int status;
  KEXPECT_EQ(child, wait(&status));
  KEXPECT_EQ(0, status);
}

static void cont_masked_test(void) {
  KTEST_BEGIN("SIGCONT continues even if masked");
  pid_t child = fork();
  if (child == 0) {
    sigset_t mask = make_sigset(SIGCONT);
    sigprocmask(SIG_BLOCK, &mask, NULL);
    kill(getpid(), SIGSTOP);
    create_file("child_continued");
    sleep_ms(SLEEP_MS);
    exit(0);
  }
  cont_masked_test_parent(child);


  KTEST_BEGIN("SIGCONT continues even if ignored");
  child = fork();
  if (child == 0) {
    struct sigaction act = {SIG_IGN, 0, 0};
    sigaction(SIGCONT, &act, NULL);
    kill(getpid(), SIGSTOP);
    create_file("child_continued");
    sleep_ms(SLEEP_MS);
    exit(0);
  }
  cont_masked_test_parent(child);


  KTEST_BEGIN("SIGCONT continues even if handled");
  child = fork();
  if (child == 0) {
    struct sigaction act = {&file_handler, 0, 0};
    sigaction(SIGCONT, &act, NULL);
    kill(getpid(), SIGSTOP);
    create_file("child_continued");
    sleep_ms(SLEEP_MS);
    exit(0);
  }
  cont_masked_test_parent(child);
  KEXPECT_EQ(true, file_exists("got_signal"));
  KEXPECT_EQ(0, unlink("got_signal"));


  KTEST_BEGIN("SIGCONT continues but doesn't run masked handled");
  child = fork();
  if (child == 0) {
    struct sigaction act = {&file_handler, 0, 0};
    sigaction(SIGCONT, &act, NULL);
    sigset_t mask = make_sigset(SIGCONT);
    sigprocmask(SIG_BLOCK, &mask, NULL);
    kill(getpid(), SIGSTOP);
    create_file("child_continued");
    sleep_ms(SLEEP_MS);
    exit(0);
  }
  cont_masked_test_parent(child);
  KEXPECT_EQ(false, file_exists("got_signal"));


  KTEST_BEGIN("SIGAPOS_FORCE_CONT cannot be sent");
  child = fork();
  if (child == 0) {
    struct sigaction act = {&file_handler, 0, 0};
    sigaction(30 /* SIGAPOS_FORCE_CONT */, &act, NULL);
    sigset_t mask = make_sigset(30);
    sigprocmask(SIG_BLOCK, &mask, NULL);
    kill(getpid(), SIGSTOP);
    create_file("child_continued");
    sleep_ms(SLEEP_MS);
    exit(0);
  }
  KEXPECT_ERRNO(EPERM, kill(child, 30 /* SIGAPOS_FORCE_CONT */));
  sleep_ms(SLEEP_MS_SMALL);
  kill(child, SIGKILL);
  KEXPECT_EQ(child, waitpid(child, NULL, 0));
  KEXPECT_EQ(false, file_exists("child_continued"));
  KEXPECT_EQ(false, file_exists("got_signal"));
}

static void repeat_signals_test(void) {
  char state_buf[20];

  KTEST_BEGIN("Multiple SIGSTOPs/SIGCONTs");
  pid_t child = fork();
  if (child == 0) {
    sigset_t mask = make_sigset(SIGCONT);
    sigprocmask(SIG_BLOCK, &mask, NULL);
    kill(getpid(), SIGSTOP);
    create_file("child_continued");
    // TODO(aoates): fix signal behavior so that sleep_ms() isn't interrupted.
    while (1) { sleep_ms(SLEEP_MS * 100); }
    exit(1);
  }

  for (int i = 0; i < 5; ++i) {
    sleep_ms(SLEEP_MS_SMALL);
    KEXPECT_STREQ("STOPPED", get_proc_state(child, state_buf));
    KEXPECT_EQ(false, file_exists("child_continued"));
    kill(child, SIGSTOP);
  }

  KEXPECT_EQ(0, kill(child, SIGCONT));
  KEXPECT_EQ(0, kill(child, SIGCONT));
  for (int i = 0; i < 5; ++i) {
    sleep_ms(SLEEP_MS_SMALL);
    KEXPECT_EQ(0, kill(child, SIGCONT));
  }
  KEXPECT_STREQ("RUNNING", get_proc_state(child, state_buf));
  KEXPECT_EQ(true, file_exists("child_continued"));
  KEXPECT_EQ(0, unlink("child_continued"));

  KEXPECT_EQ(0, kill(child, SIGKILL));
  int status;
  KEXPECT_EQ(child, wait(&status));
  KEXPECT_TRUE(WIFSIGNALED(status));
  KEXPECT_EQ(SIGKILL, WTERMSIG(status));
}

// Note: the behavior tested below is not actually correct --- SIGCONT shouldn't
// interrupt blocking threads.  This test exercises the scenarios, at least.
static void sigcont_sleeping_test(void) {
  char state_buf[20];
  KTEST_BEGIN("SIGCONT sleeping process thread (SIGCONT unmasked)");

  pid_t child = fork();
  if (child == 0) {
    exit(sleep_ms(SLEEP_MS * 100));
  }

  sleep_ms(SLEEP_MS_SMALL);
  KEXPECT_STREQ("RUNNING", get_proc_state(child, state_buf));
  kill(child, SIGSTOP);
  sleep_ms(SLEEP_MS_SMALL);
  KEXPECT_STREQ("STOPPED", get_proc_state(child, state_buf));
  KEXPECT_EQ(0, kill(child, SIGCONT));

  // TODO(aoates): fix this behavior --- the sleep above should finish, not be
  // interrupted.
  int status;
  KEXPECT_EQ(child, waitpid(child, &status, 0));
  KEXPECT_GE(status, SLEEP_MS);
  KEXPECT_LE(status, SLEEP_MS * 100);


  KTEST_BEGIN("SIGCONT sleeping process thread (SIGCONT masked)");

  child = fork();
  if (child == 0) {
    sigset_t mask = make_sigset(SIGCONT);
    sigprocmask(SIG_BLOCK, &mask, NULL);
    exit(sleep_ms(SLEEP_MS * 100));
  }

  sleep_ms(SLEEP_MS_SMALL);
  KEXPECT_STREQ("RUNNING", get_proc_state(child, state_buf));
  kill(child, SIGSTOP);
  sleep_ms(SLEEP_MS_SMALL);
  KEXPECT_STREQ("STOPPED", get_proc_state(child, state_buf));
  KEXPECT_EQ(0, kill(child, SIGCONT));

  // TODO(aoates): fix this behavior --- the sleep above should finish, not be
  // interrupted.
  KEXPECT_EQ(child, waitpid(child, &status, 0));
  KEXPECT_GE(status, SLEEP_MS);
  KEXPECT_LE(status, SLEEP_MS * 100);


  KTEST_BEGIN("SIGCONT sleeping process thread (SIGCONT handled)");

  child = fork();
  if (child == 0) {
    struct sigaction act = {&file_handler, 0, 0};
    sigaction(SIGCONT, &act, NULL);
    exit(sleep_ms(SLEEP_MS * 100));
  }

  sleep_ms(SLEEP_MS_SMALL);
  KEXPECT_STREQ("RUNNING", get_proc_state(child, state_buf));
  kill(child, SIGSTOP);
  sleep_ms(SLEEP_MS_SMALL);
  KEXPECT_STREQ("STOPPED", get_proc_state(child, state_buf));
  KEXPECT_EQ(0, kill(child, SIGCONT));

  // This one is correct --- the sleep should be interrupted.
  KEXPECT_EQ(child, waitpid(child, &status, 0));
  KEXPECT_GE(status, SLEEP_MS);
  KEXPECT_LE(status, SLEEP_MS * 100);
  KEXPECT_TRUE(file_exists("got_signal"));
  KEXPECT_EQ(0, unlink("got_signal"));


  KTEST_BEGIN("SIGCONT sleeping process thread (SIGCONT ignored)");

  child = fork();
  if (child == 0) {
    struct sigaction act = {SIG_IGN, 0, 0};
    sigaction(SIGCONT, &act, NULL);
    exit(sleep_ms(SLEEP_MS * 100));
  }

  sleep_ms(SLEEP_MS_SMALL);
  KEXPECT_STREQ("RUNNING", get_proc_state(child, state_buf));
  kill(child, SIGSTOP);
  sleep_ms(SLEEP_MS_SMALL);
  KEXPECT_STREQ("STOPPED", get_proc_state(child, state_buf));
  KEXPECT_EQ(0, kill(child, SIGCONT));

  // TODO(aoates): fix this behavior --- the sleep above should finish, not be
  // interrupted.
  KEXPECT_EQ(child, waitpid(child, &status, 0));
  KEXPECT_GE(status, SLEEP_MS);
  KEXPECT_LE(status, SLEEP_MS * 100);
  KEXPECT_FALSE(file_exists("got_signal"));
}

static void signal_interaction_test(void) {
  char state_buf[20];

  KTEST_BEGIN("SIGKILL (term) while stopped");
  pid_t child;
  if ((child = fork()) == 0) {
    kill(getpid(), SIGSTOP);
    create_file("child_continued");
    exit(1);
  }

  sleep_ms(SLEEP_MS_SMALL);
  KEXPECT_STREQ("STOPPED", get_proc_state(child, state_buf));
  KEXPECT_EQ(0, kill(child, SIGKILL));
  int status;
  KEXPECT_EQ(child, wait(&status));
  KEXPECT_EQ(128 + SIGKILL, status);
  KEXPECT_EQ(false, file_exists("child_continued"));


  KTEST_BEGIN("SIGQUIT (term + core) while stopped");
  if ((child = fork()) == 0) {
    kill(getpid(), SIGSTOP);
    create_file("child_continued");
    exit(1);
  }

  sleep_ms(SLEEP_MS_SMALL);
  KEXPECT_STREQ("STOPPED", get_proc_state(child, state_buf));
  KEXPECT_EQ(0, kill(child, SIGQUIT));
  KEXPECT_EQ(child, wait(&status));
  KEXPECT_EQ(128 + SIGQUIT, status);
  KEXPECT_EQ(false, file_exists("child_continued"));


  KTEST_BEGIN("SIGUSR1 while stopped");
  if ((child = fork()) == 0) {
    kill(getpid(), SIGSTOP);
    create_file("child_continued");
    exit(1);
  }

  sleep_ms(SLEEP_MS_SMALL);
  KEXPECT_STREQ("STOPPED", get_proc_state(child, state_buf));
  KEXPECT_EQ(0, kill(child, SIGUSR1));
  KEXPECT_EQ(child, wait(&status));
  KEXPECT_EQ(128 + SIGUSR1, status);
  KEXPECT_EQ(false, file_exists("child_continued"));


  KTEST_BEGIN("SIGURG (default ignored) while stopped");
  if ((child = fork()) == 0) {
    kill(getpid(), SIGSTOP);
    create_file("child_continued");
    exit(1);
  }

  sleep_ms(SLEEP_MS_SMALL);
  KEXPECT_STREQ("STOPPED", get_proc_state(child, state_buf));
  KEXPECT_EQ(0, kill(child, SIGURG));
  for (int i = 0; i < 5; ++i) {
    sleep_ms(SLEEP_MS_SMALL);
    KEXPECT_STREQ("STOPPED", get_proc_state(child, state_buf));
  }
  KEXPECT_EQ(false, file_exists("child_continued"));

  KEXPECT_EQ(0, kill(child, SIGKILL));
  KEXPECT_EQ(child, wait(&status));
  KEXPECT_EQ(128 + SIGKILL, status);


  KTEST_BEGIN("Masked SIGUSR1 while stopped");
  if ((child = fork()) == 0) {
    sigset_t set = make_sigset(SIGUSR1);
    sigprocmask(SIG_BLOCK, &set, NULL);
    kill(getpid(), SIGSTOP);
    create_file("child_continued");
    kill(getpid(), SIGSTOP);
    sigprocmask(SIG_UNBLOCK, &set, NULL);
    create_file("child_continued2");
    exit(1);
  }

  sleep_ms(SLEEP_MS_SMALL);
  KEXPECT_STREQ("STOPPED", get_proc_state(child, state_buf));
  KEXPECT_EQ(0, kill(child, SIGUSR1));
  for (int i = 0; i < 5; ++i) {
    sleep_ms(SLEEP_MS_SMALL);
    KEXPECT_STREQ("STOPPED", get_proc_state(child, state_buf));
  }
  KEXPECT_EQ(false, file_exists("child_continued"));

  KEXPECT_EQ(0, kill(child, SIGCONT));
  for (int i = 0; i < 5; ++i) sleep_ms(SLEEP_MS_SMALL);
  KEXPECT_EQ(true, file_exists("child_continued"));
  KEXPECT_EQ(false, file_exists("child_continued2"));

  KEXPECT_EQ(0, kill(child, SIGCONT));
  KEXPECT_EQ(child, wait(&status));
  KEXPECT_EQ(128 + SIGUSR1, status);
  KEXPECT_EQ(true, file_exists("child_continued"));
  KEXPECT_EQ(false, file_exists("child_continued2"));
  KEXPECT_EQ(0, unlink("child_continued"));


  KTEST_BEGIN("SIGUSR1 with handler while stopped");
  if ((child = fork()) == 0) {
    signal(SIGUSR1, (void (*)(int))0x1234);
    kill(getpid(), SIGSTOP);
    create_file("child_continued");
    exit(0);
  }

  sleep_ms(SLEEP_MS_SMALL);
  KEXPECT_STREQ("STOPPED", get_proc_state(child, state_buf));
  KEXPECT_EQ(0, kill(child, SIGSTOP));
  KEXPECT_EQ(0, kill(child, SIGUSR1));
  for (int i = 0; i < 5; ++i) {
    sleep_ms(SLEEP_MS_SMALL);
    KEXPECT_STREQ("STOPPED", get_proc_state(child, state_buf));
  }
  KEXPECT_EQ(false, file_exists("child_continued"));

  KEXPECT_EQ(0, kill(child, SIGKILL));
  KEXPECT_EQ(child, wait(&status));
  KEXPECT_EQ(128 + SIGKILL, status);


  KTEST_BEGIN("SIGUSR1 with handler while stopped (verify queued)");
  if ((child = fork()) == 0) {
    signal(SIGUSR1, &file_handler);
    kill(getpid(), SIGSTOP);
    create_file("child_continued");
    exit(0);
  }

  sleep_ms(SLEEP_MS_SMALL);
  KEXPECT_STREQ("STOPPED", get_proc_state(child, state_buf));
  KEXPECT_EQ(0, kill(child, SIGSTOP));
  KEXPECT_EQ(0, kill(child, SIGUSR1));
  for (int i = 0; i < 5; ++i) {
    sleep_ms(SLEEP_MS_SMALL);
    KEXPECT_STREQ("STOPPED", get_proc_state(child, state_buf));
  }
  KEXPECT_EQ(false, file_exists("child_continued"));
  KEXPECT_EQ(false, file_exists("got_signal"));

  KEXPECT_EQ(0, kill(child, SIGCONT));
  for (int i = 0; i < 5; ++i) sleep_ms(SLEEP_MS_SMALL);
  KEXPECT_EQ(true, file_exists("child_continued"));
  KEXPECT_EQ(true, file_exists("got_signal"));

  KEXPECT_EQ(child, wait(&status));
  KEXPECT_EQ(0, status);
  KEXPECT_EQ(0, unlink("child_continued"));
  KEXPECT_EQ(0, unlink("got_signal"));


  KTEST_BEGIN("SIGTSTP with handler while stopped");
  if ((child = fork()) == 0) {
    signal(SIGTSTP, (void (*)(int))0x1234);
    kill(getpid(), SIGSTOP);
    create_file("child_continued");
    exit(0);
  }

  sleep_ms(SLEEP_MS_SMALL);
  KEXPECT_STREQ("STOPPED", get_proc_state(child, state_buf));
  KEXPECT_EQ(0, kill(child, SIGSTOP));
  KEXPECT_EQ(0, kill(child, SIGTSTP));
  for (int i = 0; i < 5; ++i) {
    sleep_ms(SLEEP_MS_SMALL);
    KEXPECT_STREQ("STOPPED", get_proc_state(child, state_buf));
  }
  KEXPECT_EQ(false, file_exists("child_continued"));

  KEXPECT_EQ(0, kill(child, SIGKILL));
  KEXPECT_EQ(child, wait(&status));
  KEXPECT_EQ(128 + SIGKILL, status);
}

static void alarm_stop_test(void) {
  char state_buf[20];

  KTEST_BEGIN("alarm() (no handler) while stopped");
  pid_t child;
  if ((child = fork()) == 0) {
    alarm_ms(100);
    kill(getpid(), SIGSTOP);
    exit(1);
  }

  int status;
  KEXPECT_EQ(child, wait(&status));
  KEXPECT_EQ(SIGALRM + 128, status);


  KTEST_BEGIN("alarm() (with handler) while stopped");
  if ((child = fork()) == 0) {
    signal(SIGALRM, &file_handler);
    alarm_ms(20);
    kill(getpid(), SIGSTOP);
    exit(1);
  }
  sleep_ms(100);
  KEXPECT_STREQ("STOPPED", get_proc_state(child, state_buf));
  KEXPECT_EQ(0, kill(child, SIGCONT));
  KEXPECT_EQ(false, file_exists("got_signal"));

  KEXPECT_EQ(child, wait(&status));
  KEXPECT_EQ(1, status);
  KEXPECT_EQ(true, file_exists("got_signal"));
  KEXPECT_EQ(0, unlink("got_signal"));
}

void stop_test(void) {
  KTEST_SUITE_BEGIN("SIGSTOP/SIGCONT tests");

  basic_stop_test();
  cont_masked_test();
  repeat_signals_test();
  sigcont_sleeping_test();
  signal_interaction_test();
  alarm_stop_test();
}
