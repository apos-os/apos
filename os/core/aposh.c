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

// A very basic shell.
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include <apos/syscall_decls.h>

#include "os/common/list.h"

#define ENABLE_TERM_COLOR 1

const char* PATH[] = {
  "/",
  "/bin",
  NULL,
};

#define READ_BUF_SIZE 1024

typedef enum {
  JOB_RUNNING,
  JOB_SUSPENDED,

  // Jobs are never in the following states.
  JOB_CONTINUED,
  JOB_DONE,
  JOB_SIGNALLED,
} job_state_t;

// A background job in the shell.
typedef struct {
  pid_t pid;
  job_state_t state;
  int jobnum;
  char* cmd;
  list_link_t link;
} job_t;

static void print_job_state(const job_t* job, job_state_t state) {
  const char* state_str = "<unknown!>";
  switch (state) {
    case JOB_RUNNING: state_str = "running"; break;
    case JOB_SUSPENDED: state_str = "suspended"; break;
    case JOB_CONTINUED: state_str = "continued"; break;
    case JOB_DONE: state_str = "done"; break;
    // TODO(aoates): print signal description
    case JOB_SIGNALLED: state_str = "signalled"; break;
  }

  printf("[%d]    %d %-9s  %s\n", job->jobnum, job->pid, state_str,
             job->cmd);
}

// State for the shell.
typedef struct {
  char tty_name[20];
  int tty_fd;
  list_t jobs;
} kshell_t;

static void parse_and_dispatch(kshell_t* shell, char* cmd);

static void test_cmd(kshell_t* shell, int argc, char* argv[]) {
  if (argc != 2) {
    printf("invalid # of args for test: expected 1, got %d\n", argc - 1);
    return;
  }

  pid_t child;
  if ((child = fork()) == 0) {
    close(shell->tty_fd);
    apos_run_ktest(argv[1]);
    exit(0);
  }

  assert(child == waitpid(child, NULL, 0));
}

// Sleeps the thread for a certain number of ms.
static void sleep_cmd(kshell_t* shell, int argc, char* argv[]) {
  if (argc != 2) {
    printf("usage: sleep <ms>\n");
    return;
  }

  sleep(atoi(argv[1]));
}

static void cd_cmd(kshell_t* shell, int argc, char* argv[]) {
  if (argc != 2) {
    printf("usage: cd <path>\n");
    return;
  }
  const int result = chdir(argv[1]);
  if (result) {
    perror("Unable to chdir");
  }
}

typedef struct {
  const char* path;
  int argc;
  char** argv;
} exec_child_args_t;

static void exec_child_func(void* arg) {
  setpgid(0, 0);

  exec_child_args_t* args = (exec_child_args_t*)arg;
  // TODO(aoates): set environment
  char* envp[] = { NULL };
  execve(args->path, args->argv, envp);
  perror(NULL);
  fprintf(stderr, "Couldn't execute %s\n", args->path);
  exit(1);
}

static int get_next_jobnum(const kshell_t* shell) {
  int jobnum = 1;

  for (list_link_t* link = shell->jobs.head; link != NULL; link = link->next) {
    job_t* job = container_of(link, job_t, link);
    assert(job->jobnum >= jobnum);
    if (job->jobnum > jobnum)
      break;
    jobnum++;
  }
  return jobnum;
}

static char* make_job_cmd(int argc, char** argv) {
  size_t len = 0;
  for (int i = 0; i < argc; ++i) {
    len += strlen(argv[i]) + 1;
  }
  char* buf = (char*)malloc(len);
  char* cbuf = buf;
  for (int i = 0; i < argc; ++i) {
    for (int j = 0; argv[i][j] != '\0'; ++j)
      *(cbuf++) = argv[i][j];
    *(cbuf++) = ' ';
  }
  *(cbuf - 1) = '\0';
  return buf;
}

static void insert_job(job_t* new_job, kshell_t* shell) {
  job_t* prev = NULL;
  for (list_link_t* link = shell->jobs.head; link != NULL; link = link->next) {
    job_t* job = container_of(link, job_t, link);
    assert(job->jobnum != new_job->jobnum);
    if (job->jobnum > new_job->jobnum) {
      break;
    }
    prev = job;
  }
  list_insert(&shell->jobs, prev ? &prev->link : NULL, &new_job->link);
}

static job_t* make_job(kshell_t* shell, pid_t pid, int argc, char** argv) {
  job_t* job = (job_t*)malloc(sizeof(job_t));
  job->pid = pid;
  job->state = JOB_RUNNING;
  job->jobnum = get_next_jobnum(shell);
  job->cmd = make_job_cmd(argc, argv);
  job->link = LIST_LINK_INIT;
  insert_job(job, shell);
  return job;
}

static job_t* find_job(kshell_t* shell, pid_t pid) {
  for (list_link_t* link = shell->jobs.head; link != NULL; link = link->next) {
    job_t* job = container_of(link, job_t, link);
    if (job->pid == pid) return job;
  }
  return NULL;
}

static void job_done(kshell_t* shell, job_t* job) {
  list_remove(&shell->jobs, &job->link);
  free(job->cmd);
  free(job);
}

static pid_t do_wait(kshell_t* shell, pid_t pid, bool block) {
  int options = WUNTRACED;
  if (!block) options |= WNOHANG;

  int status;
  pid_t wait_pid;
  wait_pid = waitpid(pid, &status, options);

  if (wait_pid > 0) {
    job_t* job = find_job(shell, wait_pid);
    assert(job);

    if (WIFEXITED(status)) {
      if (!block) print_job_state(job, JOB_DONE);
      job_done(shell, job);
    } else if (WIFSIGNALED(status)) {
      print_job_state(job, JOB_SIGNALLED);
      job_done(shell, job);
    } else {
      assert(WIFSTOPPED(status));
      print_job_state(job, JOB_SUSPENDED);
      job->state = JOB_SUSPENDED;
    }
  }

  return wait_pid;
}

static void continue_job(kshell_t* shell, job_t* job) {
  // TODO(aoates): check for error.
  assert(job->state == JOB_SUSPENDED);
  print_job_state(job, JOB_CONTINUED);
  kill(job->pid, SIGCONT);
  job->state = JOB_RUNNING;
}

static void put_job_fg(kshell_t* shell, job_t* job, bool cont) {
  // TODO(aoates): check for errors on these.
  tcsetpgrp(shell->tty_fd, job->pid);

  if (cont) continue_job(shell, job);
  do_wait(shell, job->pid, true);
  assert(0 == tcsetpgrp(shell->tty_fd, getpgid(0)));
}

static void put_job_bg(kshell_t* shell, job_t* job, bool cont) {
  if (cont) continue_job(shell, job);
}

void do_exec_cmd(kshell_t* shell, const char* path, int argc, char** argv) {
  assert(argc >= 1);

  exec_child_args_t args;
  args.path = path;
  args.argc = argc;
  args.argv = argv;

  pid_t child_pid = fork();
  if (child_pid < 0) {
    perror("Unable to fork");
  } else if (child_pid == 0) {
    exec_child_func(&args);
    exit(1);  // Should never get here.
  } else {
    job_t* job = make_job(shell, child_pid, argc, argv);
    assert(0 == setpgid(job->pid, job->pid));
    put_job_fg(shell, job, false);
  }
}

static void fg_bg_cmd(kshell_t* shell, int argc, char** argv, bool is_fg) {
  const char* cmd_name = is_fg ? "fg" : "bg";
  if (argc > 2) {
    printf("Usage: %s [optional %%jobnum]\n", cmd_name);
    return;
  }
  if (shell->jobs.head == NULL) {
    printf("%s: no current jobs\n", cmd_name);
    return;
  }

  int jobnum = -1;
  if (argc == 2) {
    if (argv[1][0] == '%') {
      jobnum = atoi(&argv[1][1]);
    }
    if (jobnum <= 0) {
      printf("invalid job number '%s'\n", argv[1]);
      return;
    }
  }

  job_t* job = NULL;
  for (list_link_t* link = shell->jobs.head; link != NULL; link = link->next) {
    job_t* cjob = container_of(link, job_t, link);
    if (jobnum == -1 || cjob->jobnum == jobnum) {
      job = cjob;
      break;
    }
  }

  if (job == NULL) {
    printf("job %d not found\n", jobnum);
    return;
  }

  if (!is_fg && job->state == JOB_RUNNING) {
    printf("bg: job already in background\n");
    return;
  }

  if (is_fg) {
    if (job->state == JOB_RUNNING) print_job_state(job, JOB_RUNNING);
    put_job_fg(shell, job, job->state == JOB_SUSPENDED);
  } else {
    assert(job->state == JOB_SUSPENDED);
    put_job_bg(shell, job, true);
  }
}

void fg_cmd(kshell_t* shell, int argc, char** argv) {
  fg_bg_cmd(shell, argc, argv, true);
}

void bg_cmd(kshell_t* shell, int argc, char** argv) {
  fg_bg_cmd(shell, argc, argv, false);
}

void jobs_cmd(kshell_t* shell, int argc, char** argv) {
  if (argc != 1) {
    fprintf(stderr, "Usage: jobs\n");
    return;
  }
  for (list_link_t* link = shell->jobs.head; link != NULL; link = link->next) {
    job_t* job = container_of(link, job_t, link);
    print_job_state(job, job->state);
  }
}

typedef struct {
  const char* name;
  void (*func)(kshell_t*, int, char*[]);
} cmd_t;

static const cmd_t CMDS[] = {
  { "_sleep", &sleep_cmd },

  { "cd", &cd_cmd },

  { "fg", &fg_cmd },
  { "bg", &bg_cmd },
  { "jobs", &jobs_cmd },

  { "test", &test_cmd },

  { 0x0, 0x0 },
};

static int is_ws(char c) {
  return c == ' ' || c == '\n' || c == '\t';
}

static void parse_and_dispatch(kshell_t* shell, char* cmd) {
  // Parse the command line string.
  int argc = 0;
  char* argv[100];
  int i = 0;
  int in_ws = 1;  // set to 1 to eat leading ws.
  while (cmd[i] != '\0') {
    if (is_ws(cmd[i])) {
      cmd[i] = '\0';
      if (!in_ws) {
        in_ws = 1;
      }
    } else if (in_ws) {
      if (argc >= 100) {
        printf("error: too many arguments\n");
        return;
      }
      argv[argc] = &cmd[i];
      argc++;
      in_ws = 0;
    }
    i++;
  }

  argv[argc] = 0x0;
  if (argc == 0) {
    return;
  }

  // Find the command.
  const cmd_t* cmd_data = &CMDS[0];
  while (cmd_data->name != 0x0) {
    if (strcmp(cmd_data->name, argv[0]) == 0) {
      cmd_data->func(shell, argc, argv);
      return;
    }
    cmd_data++;
  }

  // Search for a binary to run.
  char* path = malloc(1024 /* VFS_MAX_PATH_LENGTH */ * 2);
  for (int i = 0; PATH[i] != NULL; ++i) {
    sprintf(path, "%s/%s", PATH[i], argv[0]);
    if (access(path, X_OK) == 0) {
      do_exec_cmd(shell, path, argc, argv);
      free(path);
      return;
    }
  }
  free(path);

  printf("error: unknown command '%s'\n", argv[0]);
}

int main(int argc, char** argv) {
  kshell_t shell = {"", -1, LIST_INIT};

  // TODO(aoates): should we attempt to setsid in case it wasn't done for us?
  // TODO(aoates): get the TTY a better way
  shell.tty_fd = dup(0);

  // TODO(aoates): is this redundant with the SIG_IGN in getty?  Should likely
  // only have one.
  sigset_t mask;
  sigemptyset(&mask);
  sigaddset(&mask, SIGTTOU);
  sigaddset(&mask, SIGTSTP);
  sigprocmask(SIG_BLOCK, &mask, NULL);
  assert(0 == tcsetpgrp(shell.tty_fd, getpgid(0)));

  // TODO(aoates): catch and handle SIGINT to clear current line.

  printf("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n");
  printf("@                     APOSH                      @\n");
  printf("@            (c) Andrew Oates 2021               @\n");
  printf("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n");

  char read_buf[READ_BUF_SIZE];

  while (1) {
#if ENABLE_TERM_COLOR
    printf("\x1b[0m");  // Reset before each prompt.
#endif
    printf("> ");
    fflush(stdout);
    int read_len = read(0, read_buf, READ_BUF_SIZE);
    if (read_len < 0) {
      perror(NULL);
      continue;
    }

    read_buf[read_len] = '\0';
    parse_and_dispatch(&shell, read_buf);

    do_wait(&shell, -1, false);
  }
}
