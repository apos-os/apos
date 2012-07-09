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

// A very basic kernel-mode shell.  Currently just for testing ld I/O.

#include <stdint.h>

#include "common/kassert.h"
#include "common/klog.h"
#include "common/kstring.h"
#include "common/kprintf.h"
#include "dev/ld.h"
#include "kmalloc.h"
#include "test/kernel_tests.h"
#include "test/ktest.h"

#define READ_BUF_SIZE 1024

static ld_t* g_io = 0;

static void ksh_printf(const char* fmt, ...) {
  char buf[1024];

  va_list args;
  va_start(args, fmt);
  kvsprintf(buf, fmt, args);
  va_end(args);
  ld_write(g_io, buf, kstrlen(buf));
}

typedef struct {
  const char* name;
  void (*func)(void);
  int run_in_all;
} test_entry_t;

static void run_all_tests();

static test_entry_t TESTS[] = {
  { "ktest", &ktest_test, 0 },

  // Running kmalloc test ruins everything else since it resets malloc state.
  { "kmalloc", &kmalloc_test, 0 },

  { "ld", &ld_test, 1 },
  { "kassert", &kassert_test, 1 },
  { "page_alloc", &page_alloc_test, 1 },
  { "page_alloc_map", &page_alloc_map_test, 1 },
  { "kthread", &kthread_test, 1 },
  { "interrupt_clobber", &interrupt_clobber_test, 1 },
  { "interrupt_save", &interrupt_save_test, 1 },
  { "kstring", &kstring_test, 1 },
  { "kprintf", &kprintf_test, 1 },

  // Fake test for running everything.
  { "all", &run_all_tests, 0 },
  { 0, 0, 0},
};

static void run_all_tests() {
  test_entry_t* e = &TESTS[0];
  while (e->name != 0x0) {
    if (e->run_in_all) {
      e->func();
    }
    e++;
  }
}

static void test_cmd(int argc, char* argv[]) {
  if (argc != 2) {
    ksh_printf("invalid # of args for test: expected 1, got %d\n",
               argc - 1);
    return;
  }

  test_entry_t* e = &TESTS[0];
  while (e->name != 0x0) {
    if (kstrcmp(argv[1], e->name) == 0) {
      ksh_printf("running test '%s'...\n", argv[1]);
      ktest_begin_all();
      e->func();
      ktest_finish_all();
      return;
    }
    e++;
  }

  ksh_printf("error: unknown test '%s'\n", argv[1]);
}

typedef struct {
  const char* name;
  void (*func)(int, char*[]);
} cmd_t;

static cmd_t CMDS[] = {
  { "test", &test_cmd },
  { 0x0, 0x0 },
};

static int is_ws(char c) {
  return c == ' ' || c == '\n' || c == '\t';
}

static void parse_and_dispatch(char* cmd) {
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
        ksh_printf("error: too many arguments\n");
        return;
      }
      argv[argc] = &cmd[i];
      argc++;
      in_ws = 0;
    }
    i++;
  }

  if (argc == 0) {
    return;
  }

  // Find the command.
  cmd_t* cmd_data = &CMDS[0];
  while (cmd_data->name != 0x0) {
    if (kstrcmp(cmd_data->name, argv[0]) == 0) {
      cmd_data->func(argc, argv);
      return;
    }
    cmd_data++;
  }

  ksh_printf("error: known command '%s'\n", argv[0]);
}

void kshell_main(ld_t* io) {
  g_io = io;

  char read_buf[READ_BUF_SIZE];
  while (1) {
    ld_write(g_io, "> ", 2);
    int read_len = ld_read(g_io, read_buf, READ_BUF_SIZE);

    read_buf[read_len] = '\0';
    //klogf("kshell: read %d bytes:\n%s\n", read_len, read_buf);

    parse_and_dispatch(read_buf);
    //ksprintf(out_buf, "You wrote: '%s'\n", read_buf);
    //ld_write(g_io, out_buf, kstrlen(out_buf));
  }
}
