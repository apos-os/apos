// Copyright 2025 Andrew Oates.  All Rights Reserved.
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
//
// A test suite that exercises basic busybox functionality.
#include <ctype.h>
#include <sys/unistd.h>

#include "all_tests.h"
#include "ktest.h"

#define BUF_SIZE 2000
#define STDOUT_FILE "_bbtest_stdout.txt"
#define STDERR_FILE "_bbtest_stderr.txt"

typedef struct {
  int status;
  char out[BUF_SIZE];
  char err[BUF_SIZE];
} cmd_result_t;

static void read_and_close(char* buf_out, const char* fname, int fd) {
  KEXPECT_EQ(0, lseek(fd, 0, SEEK_SET));
  size_t buflen = BUF_SIZE - 1;
  ssize_t total_bytes = 0;
  while (buflen > 0) {
    ssize_t bytes = read(fd, buf_out + total_bytes, buflen);
    KEXPECT_GE(bytes, 0);
    if (bytes == 0) break; // EOF
    total_bytes += bytes;
    buflen -= bytes;
  }
  buf_out[total_bytes] = 0;
  KEXPECT_LT(total_bytes, BUF_SIZE - 1);  // Make sure buffer is big enough.
  KEXPECT_EQ(0, close(fd));
  KEXPECT_EQ(0, unlink(fname));
}

static int run_bb(const char* cmd[], cmd_result_t* result) {
  int stdout_fd = open(STDOUT_FILE, O_RDWR | O_CREAT | O_TRUNC, VFS_S_IRWXU);
  KEXPECT_GE(stdout_fd, 0);
  int stderr_fd = open(STDERR_FILE, O_RDWR | O_CREAT | O_TRUNC, VFS_S_IRWXU);
  KEXPECT_GE(stderr_fd, 0);

  pid_t child = fork();
  if (child == 0) {
    // In the child.  Redirect stdout/stderr and run the command.
    dup2(stdout_fd, 1);
    dup2(stderr_fd, 2);
    size_t args;
    for (args = 0; cmd[args] != NULL; ++args);
    char** argv = malloc(sizeof(char*) * args + 1);
    for (size_t i = 0; i < args; ++i) {
      argv[i] = strdup(cmd[i]);
    }
    argv[args] = NULL;
    execv("/bin/busybox", argv);
    apos_klog("UNEXPECTED: execv failed in busybox test\n");
    exit(1);
  }

  KEXPECT_EQ(child, waitpid(child, &result->status, 0));

  // Read stdout and stderr.
  read_and_close(result->out, STDOUT_FILE, stdout_fd);
  read_and_close(result->err, STDERR_FILE, stderr_fd);
  return result->status;
}

static char* stripr(char* str) {
  size_t len = strlen(str);
  while (len > 0 && isspace((int)str[len - 1])) {
    str[len - 1] = '\0';
    len--;
  }
  return str;
}

static void ascii_test(void) {
  KTEST_BEGIN("busybox: ascii test");
  cmd_result_t res;
  KEXPECT_EQ(0, run_bb((const char*[])
                       {"ascii", NULL},
                       &res));
  KEXPECT_MULTILINE_STREQ(res.out,
    "Dec Hex    Dec Hex    Dec Hex  Dec Hex  Dec Hex  Dec Hex   Dec Hex   Dec Hex\n"
    "  0 00 NUL  16 10 DLE  32 20    48 30 0  64 40 @  80 50 P   96 60 `  112 70 p\n"
    "  1 01 SOH  17 11 DC1  33 21 !  49 31 1  65 41 A  81 51 Q   97 61 a  113 71 q\n"
    "  2 02 STX  18 12 DC2  34 22 \"  50 32 2  66 42 B  82 52 R   98 62 b  114 72 r\n"
    "  3 03 ETX  19 13 DC3  35 23 #  51 33 3  67 43 C  83 53 S   99 63 c  115 73 s\n"
    "  4 04 EOT  20 14 DC4  36 24 $  52 34 4  68 44 D  84 54 T  100 64 d  116 74 t\n"
    "  5 05 ENQ  21 15 NAK  37 25 %  53 35 5  69 45 E  85 55 U  101 65 e  117 75 u\n"
    "  6 06 ACK  22 16 SYN  38 26 &  54 36 6  70 46 F  86 56 V  102 66 f  118 76 v\n"
    "  7 07 BEL  23 17 ETB  39 27 '  55 37 7  71 47 G  87 57 W  103 67 g  119 77 w\n"
    "  8 08 BS   24 18 CAN  40 28 (  56 38 8  72 48 H  88 58 X  104 68 h  120 78 x\n"
    "  9 09 HT   25 19 EM   41 29 )  57 39 9  73 49 I  89 59 Y  105 69 i  121 79 y\n"
    " 10 0a NL   26 1a SUB  42 2a *  58 3a :  74 4a J  90 5a Z  106 6a j  122 7a z\n"
    " 11 0b VT   27 1b ESC  43 2b +  59 3b ;  75 4b K  91 5b [  107 6b k  123 7b {\n"
    " 12 0c FF   28 1c FS   44 2c ,  60 3c <  76 4c L  92 5c \\  108 6c l  124 7c |\n"
    " 13 0d CR   29 1d GS   45 2d -  61 3d =  77 4d M  93 5d ]  109 6d m  125 7d }\n"
    " 14 0e SO   30 1e RS   46 2e .  62 3e >  78 4e N  94 5e ^  110 6e n  126 7e ~\n"
    " 15 0f SI   31 1f US   47 2f /  63 3f ?  79 4f O  95 5f _  111 6f o  127 7f DEL\n"
    );
}

static void date_test(void) {
  KTEST_BEGIN("busybox: date test");
  cmd_result_t res;
  KEXPECT_EQ(0, run_bb((const char*[])
                       {"date", "-u", "-d", "2025-11-01-12:52:15", NULL},
                       &res));
  KEXPECT_STREQ(stripr(res.out), "Fri Oct 31 12:52:15 UTC 2025");

  KEXPECT_EQ(1, run_bb((const char*[])
                       {"date", "-u", "-d", "-1234", NULL},
                       &res));
  KEXPECT_STREQ(stripr(res.err), "date: invalid date '-1234'");
}

void busybox_tests(void) {
  KTEST_SUITE_BEGIN("busybox tests");
  ascii_test();
  date_test();
}
