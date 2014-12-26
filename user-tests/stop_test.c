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

#include "ktest.h"
#include "all_tests.h"

#define SLEEP_MS 50
#define SLEEP_MS_SMALL 20

static void null_handler(int sig) {}

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
  sleep_ms(SLEEP_MS);
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
    struct sigaction act = {&null_handler, 0, 0};
    sigaction(SIGCONT, &act, NULL);
    kill(getpid(), SIGSTOP);
    create_file("child_continued");
    sleep_ms(SLEEP_MS);
    exit(0);
  }
  cont_masked_test_parent(child);
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
    sleep_ms(SLEEP_MS * 100);
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
  KEXPECT_EQ(child, wait(NULL));
}

void stop_test(void) {
  KTEST_SUITE_BEGIN("SIGSTOP/SIGCONT tests");

  basic_stop_test();
  cont_masked_test();
  repeat_signals_test();
}
