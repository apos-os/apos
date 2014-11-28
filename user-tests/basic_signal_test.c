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
#include <unistd.h>
#include <signal.h>
#include <stdbool.h>
#include <sys/wait.h>
#include <time.h>

#include <apos/sleep.h>
#include <apos/syscall.h>

#include "ktest.h"
#include "all_tests.h"

struct sigaction make_sigaction(void (*handler)(int)) {
  struct sigaction new_action;
  new_action.sa_handler = handler;
  sigemptyset(&new_action.sa_mask);
  new_action.sa_flags = 0;
  return new_action;
}

static bool got_signal = false;
static void signal_action(int sig) {
  printf("caught signal\n");
  got_signal = true;
}

static void alarm_test(void) {
  KTEST_BEGIN("alarm() test");
  got_signal = false;

  struct sigaction new_action, old_action;
  new_action = make_sigaction(&signal_action);
  KEXPECT_EQ(0, sigaction(SIGALRM, &new_action, &old_action));
  alarm(1);
  sleep(2);  // TODO(aoates): use usleep

  KEXPECT_EQ(true, got_signal);

  KEXPECT_EQ(0, sigaction(SIGALRM, &old_action, NULL));
}

static void signal_test(void) {
  KTEST_BEGIN("cross-process signal test");
  got_signal = false;

  pid_t child;
  if (!(child = fork())) {
    struct sigaction new_action = make_sigaction(&signal_action);

    int result = sigaction(SIGUSR1, &new_action, NULL);
    if (result) {
      perror("sigaction in child failed");
      exit(1);
    }

    sleep_ms(200);
    exit(got_signal ? 0 : 1);
  }

  // In parent.
  sleep_ms(100);  // Let the child run.  Not really safe.
  kill(child, SIGUSR1);
  int exit_status;
  KEXPECT_EQ(child, wait(&exit_status));
  KEXPECT_EQ(0, exit_status);
}

static void catch_sigfpe(int sig) {
  exit(!(sig == SIGFPE));
}

static void sigfpe_test(void) {
  KTEST_BEGIN("SIGFPE handling");

  pid_t child;
  if ((child = fork()) == 0) {
    struct sigaction new_action = make_sigaction(&catch_sigfpe);
    int result = sigaction(SIGFPE, &new_action, NULL);
    if (result) {
      perror("sigaction in child failed");
      exit(1);
    }

    int x = 5;
    int y = 0;
    x = x / y;
    fprintf(stderr, "Got past divide-by-zero!\n");
    exit(1);
  }

  int status;
  KEXPECT_EQ(child, wait(&status));
  KEXPECT_EQ(0, status);
}

static void catch_sigsegv(int sig) {
  // TODO(aoates): test the signal metadata, once that's generated.
  exit(!(sig == SIGSEGV));
}

static void sigsegv_test(void) {
  KTEST_BEGIN("SIGSEGV handling");

  pid_t child;
  if ((child = fork()) == 0) {
    struct sigaction new_action = make_sigaction(&catch_sigsegv);
    int result = sigaction(SIGSEGV, &new_action, NULL);
    if (result) {
      perror("sigaction in child failed");
      exit(1);
    }

    int x = *(int*)(0x123);
    x = x * 10;  // Stupid compiler...
    fprintf(stderr, "Got past segfault!\n");
    exit(1);
  }

  int status;
  KEXPECT_EQ(child, wait(&status));
  KEXPECT_EQ(0, status);
}

static void sigsys_test(void) {
  KTEST_BEGIN("SIGSYS handling");

  pid_t child;
  if ((child = fork()) == 0) {
    struct sigaction act = make_sigaction(&signal_action);
    if (sigaction(SIGSYS, &act, NULL) != 0) {
      perror("sigaction failed");
      exit(1);
    }

    long syscalls[] = {-5, 10000};
    for (int i = 0; i < 2; ++i) {
      got_signal = false;
      long result = do_syscall(syscalls[i], 1, 2, 3, 4, 5, 6);
      if (result != -ENOTSUP) {
        fprintf(stderr, "unexpected do_syscall result: %ld\n", result);
        exit(1);
      }
      if (!got_signal) {
        fprintf(stderr, "didn't get SIGSYS as expected\n");
        exit(1);
      }
    }
    exit(0);
  }

  int status;
  KEXPECT_EQ(child, wait(&status));
  KEXPECT_EQ(0, status);
}

static void sigchld_test(void) {
  KTEST_BEGIN("SIGCHLD handling");

  pid_t child;
  if ((child = fork()) == 0) {
    got_signal = false;
    struct sigaction act = make_sigaction(&signal_action);
    if (sigaction(SIGCHLD, &act, NULL) != 0) {
      perror("sigaction failed");
      exit(1);
    }

    pid_t sub_child;
    if ((sub_child = fork()) == 0) {
      exit(0);
    }

    // TODO(aoates): test interaction of SIGCHLD and wait().
    sleep_ms(100);  // TODO(aoates): use sigwait()
    if (!got_signal) {
      fprintf(stderr, "didn't get SIGCHLD when child exited\n");
      exit(1);
    }

    exit(0);
  }

  int status;
  KEXPECT_EQ(child, wait(&status));
  KEXPECT_EQ(0, status);
}

static void sleep_ms_interrupt_test(void) {
  KTEST_BEGIN("sleep_ms() interrupted by signal");

  pid_t child;
  if ((child = fork()) == 0) {
    got_signal = false;
    struct sigaction act = make_sigaction(&signal_action);
    if (sigaction(SIGUSR1, &act, NULL) != 0) {
      perror("sigaction failed");
      exit(1);
    }

    int result = sleep_ms(100);
    exit(result);
  }

  sleep_ms(10);
  KEXPECT_EQ(0, kill(child, SIGURG)); // Should be ignored.

  sleep_ms(50);
  KEXPECT_EQ(0, kill(child, SIGUSR1)); // Should wake up sleep_ms().

  int status;
  KEXPECT_EQ(child, wait(&status));
  KEXPECT_GE(status, 20);
  KEXPECT_LE(status, 50);
}

static void sleep_ms_send_term_sig_test(int sig) {
  KTEST_BEGIN("sleep_ms() interrupted by signal");

  pid_t child;
  if ((child = fork()) == 0) {
    exit(sleep_ms(10 * 1000));
  }

  sleep_ms(50);
  time_t start_time = time(NULL);
  KEXPECT_EQ(0, kill(child, sig));
  time_t end_time = time(NULL);
  KEXPECT_LE(end_time - start_time, 1);

  int status;
  KEXPECT_EQ(child, wait(&status));
  KEXPECT_EQ(status, 128 + sig);
}

static void blocked_signal_test(void) {
  KTEST_BEGIN("blocked signal test");

  pid_t child;
  if ((child = fork()) == 0) {
    struct sigaction action = make_sigaction(&signal_action);
    got_signal = false;
    if (sigaction(SIGUSR1, &action, NULL) != 0) {
      perror("sigaction failed");
      exit(1);
    }

    sigset_t orig_mask;
    if (sigprocmask(0, NULL, &orig_mask) != 0) {
      perror("sigprocmask failed");
      exit(1);
    }

    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGUSR1);
    if (sigprocmask(SIG_BLOCK, &mask, NULL) != 0) {
      perror("sigprocmask failed");
      exit(1);
    }

    sigset_t pending;
    sigpending(&pending);
    if (sigismember(&pending, SIGUSR1)) {
      fprintf(stderr, "SIGUSR should not be pending\n");
      exit(1);
    }

    raise(SIGUSR1);

    sigpending(&pending);
    if (!sigismember(&pending, SIGUSR1)) {
      fprintf(stderr, "SIGUSR should be pending\n");
      exit(1);
    }

    if (sleep_ms(100) != 0) {
      perror("sleep_ms() didn't return 0");
      exit(1);
    }
    if (got_signal) {
      fprintf(stderr, "got SIGUSR that should be blocked\n");
      exit(1);
    }

    if (sigprocmask(SIG_SETMASK, &orig_mask, NULL) != 0) {
      perror("sigprocmask failed");
      exit(1);
    }
    if (!got_signal) {
      fprintf(stderr, "unblocked SIGUSR wasn't delivered\n");
      exit(1);
    }
    exit(0);
  }

  int status;
  KEXPECT_EQ(child, wait(&status));
  KEXPECT_EQ(0, status);
}

bool saw_usr1, got_past_usr1_raise, saw_usr2;
static void raise_handler(int sig) {
  assert(sig == SIGUSR1 || sig == SIGUSR2);
  if (sig == SIGUSR1) {
    saw_usr1 = true;
    raise(SIGUSR2);
    got_past_usr1_raise = true;
  } else {
    saw_usr2 = true;
  }
}

// Test what happens when a signal is raised in a signal handler that is blocked
// by that handler's mask.  This verifies that we correctly re-assign signals in
// the sigreturn syscall.
static void blocked_signal_raised_in_handler_test(void) {
  KTEST_BEGIN("raise blocked signal in handler test");

  pid_t child;
  if ((child = fork()) == 0) {
    struct sigaction action = make_sigaction(&raise_handler);
    sigaddset(&action.sa_mask, SIGUSR2);
    sigaction(SIGUSR1, &action, NULL);
    sigaction(SIGUSR2, &action, NULL);

    saw_usr1 = got_past_usr1_raise = saw_usr2 = false;
    raise(SIGUSR1);
    if (!saw_usr1) {
      fprintf(stderr, "SIGUSR1 not raised\n");
      exit(1);
    }

    if (!got_past_usr1_raise) {
      fprintf(stderr, "SIGUSR2 raised before got_past_usr1_raise set "
              "(sa_mask not working?)\n");
      exit(1);
    }

    if (!saw_usr2) {
      fprintf(stderr, "SIGUSR2 not raised\n");
      exit(1);
    }

    exit(0);
  }
  int status;
  KEXPECT_EQ(child, wait(&status));
  KEXPECT_EQ(0, status);
}

static void sa_mask_test_handler(int sig) {
  raise(SIGUSR2);
  // If SIGUSR2 is masked, we should get here.
  raise(SIGKILL);
}

static void sa_mask_test(void) {
  KTEST_BEGIN("signal handler sa_mask test");

  pid_t child;
  if ((child = fork()) == 0) {
    struct sigaction action = make_sigaction(&sa_mask_test_handler);
    sigaddset(&action.sa_mask, SIGUSR2);
    sigaction(SIGUSR1, &action, NULL);

    raise(SIGUSR1);
    fprintf(stderr, "got past SIGKILL; shouldn't have!");
    exit(1);  // Shouldn't get here.
  }
  int status;
  KEXPECT_EQ(child, wait(&status));
  // TODO(aoates): use the portable macros for this.
  KEXPECT_EQ(128 + SIGKILL, status);


  KTEST_BEGIN("signal handler masks signal being raised");
  if ((child = fork()) == 0) {
    struct sigaction action = make_sigaction(&sa_mask_test_handler);
    sigaction(SIGUSR2, &action, NULL);

    raise(SIGUSR2);
    fprintf(stderr, "got past SIGKILL; shouldn't have!");
    exit(1);  // Shouldn't get here.
  }
  KEXPECT_EQ(child, wait(&status));
  // TODO(aoates): use the portable macros for this.
  KEXPECT_EQ(128 + SIGKILL, status);
}

void basic_signal_test(void) {
  KTEST_SUITE_BEGIN("basic signal tests");

  if (run_slow_tests) {
    alarm_test();
  }

  signal_test();
  sigfpe_test();
  sigsegv_test();
  sigsys_test();
  sigchld_test();

  sleep_ms_interrupt_test();
  sleep_ms_send_term_sig_test(SIGPIPE);  // default TERM
  sleep_ms_send_term_sig_test(SIGQUIT);  // default TERM_AND_CORE

  blocked_signal_test();
  blocked_signal_raised_in_handler_test();
  sa_mask_test();

  // TODO(aoates): test nested signal handling.
}
