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

#include "common/errno.h"
#include "common/hash.h"
#include "common/io.h"
#include "common/kassert.h"
#include "common/klog.h"
#include "common/kstring.h"
#include "common/kprintf.h"
#include "dev/ata/ata.h"
#include "dev/block.h"
#include "dev/ld.h"
#include "dev/timer.h"
#include "kmalloc.h"
#include "proc/sleep.h"
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
  { "kthread_pool", &kthread_pool_test, 1 },
  { "interrupt_clobber", &interrupt_clobber_test, 1 },
  { "interrupt_save", &interrupt_save_test, 1 },
  { "kstring", &kstring_test, 1 },
  { "kprintf", &kprintf_test, 1 },
  { "hashtable", &hashtable_test, 1 },
  { "ramdisk", &ramdisk_test, 1 },
  { "slab_alloc", &slab_alloc_test, 1 },
  { "ata", &ata_test, 0 },  // Don't run by default so we don't muck up our FS.

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

static void meminfo_cmd(int argc, char* argv[]) {
  kmalloc_log_state();
}

static void hash_cmd(int argc, char* argv[]) {
  if (argc != 2) {
    ksh_printf("usage: hash <number>\n");
    return;
  }
  uint32_t x = atou(argv[1]);
  uint32_t h = fnv_hash(x);
  ksh_printf("%u (0x%x)\n", h, h);
}

// Reads a block from a block device.
static void b_read_cmd(int argc, char* argv[]) {
  if (argc != 3) {
    ksh_printf("usage: b_read <block dev> <block>\n");
    return;
  }

  block_dev_t* b = ata_get_block_dev(atou(argv[1]));
  if (!b) {
    ksh_printf("error: unknown block device %s\n", argv[1]);
    return;
  }

  uint32_t block = atou(argv[2]);

  char buf[4096];
  kmemset(buf, 0x0, 4096);
  int error = b->read(b, block, buf, 4096);
  if (error < 0) {
    ksh_printf("error: %s\n", errorname(-error));
    return;
  }

  ksh_printf("read %d bytes:\n", error);
  buf[error] = '\0';
  ksh_printf(buf);
  ksh_printf("\n");
}

// Writes a block to a block device.
static void b_write_cmd(int argc, char* argv[]) {
  if (argc != 4) {
    ksh_printf("usage: b_write <block dev> <block> <data>\n");
    return;
  }

  block_dev_t* b = ata_get_block_dev(atou(argv[1]));
  if (!b) {
    ksh_printf("error: unknown block device %s\n", argv[1]);
    return;
  }

  uint32_t block = atou(argv[2]);

  char buf[4096];
  kmemset(buf, 0x0, 4096);
  kstrcpy(buf, argv[3]);
  int error = b->write(b, block, buf, 4096);
  if (error < 0) {
    ksh_printf("error: %s\n", errorname(-error));
    return;
  }

  ksh_printf("wrote %d bytes\n", error);
}

// Simple pager for the kernel log.  With no arguments, prints the next few
// lines of the log (and the current offset).  With one argument, prints the log
// starting at the given offset.
static void klog_cmd(int argc, char* argv[]) {
  static int offset = 0;
  if (argc < 1 || argc > 2) {
    ksh_printf("usage: klog [offset]\n");
    return;
  }

  if (argc == 2) {
    offset = atou(argv[1]);
  }
  char buf[1024];
  int read = klog_read(offset, buf, 1024);

  // Find the last newline, and truncate the last line (if multi-line).
  while (buf[read] != '\n' && read > 0) read--;
  if (read > 0) buf[read] = '\0';

  // Only show up to 20 lines.
  const int MAX_LINES = 20;
  int lines = 0;
  int cline_length = 0;
  for (int i = 0; i < read; ++i) {
    cline_length++;
    if (buf[i] == '\n' || cline_length > 80) {
      lines++;
      cline_length = 0;
    }
    if (lines > MAX_LINES) {
      read = i;
      buf[i] = '\0';
      break;
    }
  }

  ksh_printf("offset: %d\n------", offset);
  ksh_printf(buf);
  ksh_printf("\n------\n");
  offset += read;
}

// Commands for doing {in,out}{b,s,l}.
#define IO_IN_CMD(name, type) \
  static void name##_cmd(int argc, char* argv[]) { \
    if (argc != 2) { \
      ksh_printf("usage: " #name " <port>\n"); \
      return; \
    } \
    uint16_t port = atou(argv[1]); \
    type val = name(port); \
    ksh_printf("0x%x\n", val); \
  }

#define IO_OUT_CMD(name, type) \
  static void name##_cmd(int argc, char* argv[]) { \
    if (argc != 3) { \
      ksh_printf("usage: " #name " <port> <value>\n"); \
      return; \
    } \
    uint16_t port = atou(argv[1]); \
    type value = (type)atou(argv[2]); \
    name(port, value); \
  }

IO_IN_CMD(inb, uint8_t);
IO_IN_CMD(ins, uint16_t);
IO_IN_CMD(inl, uint32_t);

IO_OUT_CMD(outb, uint8_t);
IO_OUT_CMD(outs, uint16_t);
IO_OUT_CMD(outl, uint32_t);

// Registers a timer to print a message at the given interval.
static void timer_cmd(int argc, char* argv[]) {
  if (argc != 4) {
    ksh_printf("usage: timer <interval_ms> <limit> <msg>\n");
    return;
  }

  void timer_cb(void* arg) {
    ksh_printf((char*)arg);
  }

  char* buf = (char*)kmalloc(kstrlen(argv[3])+1);
  kstrcpy(buf, argv[3]);
  int result = register_timer_callback(atou(argv[1]), atou(argv[2]),
                                       &timer_cb, buf);
  if (result < 0) {
    ksh_printf("Could not register timer: %s\n", errorname(-result));
    kfree(buf);
  }
}

// Sleeps the thread for a certain number of ms.
static void sleep_cmd(int argc, char* argv[]) {
  if (argc != 2) {
    ksh_printf("usage: sleep <ms>\n");
    return;
  }

  ksleep(atou(argv[1]));
}

typedef struct {
  const char* name;
  void (*func)(int, char*[]);
} cmd_t;

static cmd_t CMDS[] = {
  { "test", &test_cmd },
  { "meminfo", &meminfo_cmd },
  { "hash", &hash_cmd },
  { "b_read", &b_read_cmd },
  { "b_write", &b_write_cmd },
  { "klog", &klog_cmd },

  { "inb", &inb_cmd },
  { "ins", &ins_cmd },
  { "inl", &inl_cmd },
  { "outb", &outb_cmd },
  { "outs", &outs_cmd },
  { "outl", &outl_cmd },

  { "timer", &timer_cmd },
  { "sleep", &sleep_cmd },

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

  ksh_printf("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n");
  ksh_printf("@                     APOS                       @\n");
  ksh_printf("@            (c) Andrew Oates 2012               @\n");
  ksh_printf("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n");

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
