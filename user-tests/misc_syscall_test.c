// Copyright 2015 Andrew Oates.  All Rights Reserved.
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

#include <apos/syscall_decls.h>
#include <apos/time_types.h>
#include <fcntl.h>
#include <sys/resource.h>
#include <termios.h>
#include <unistd.h>

#include "ktest.h"

static void apos_get_time_test(void) {
  KTEST_SUITE_BEGIN("apos_get_time() test");
  KTEST_BEGIN("apos_get_time(): basic test");
  struct apos_tm tm;
  memset(&tm, 0, sizeof(tm));

  KEXPECT_EQ(0, apos_get_time(&tm));
  KEXPECT_GE(tm.tm_year, 2015 - 1900);
  KEXPECT_LE(tm.tm_year, 3000 - 1900);
  KEXPECT_GE(tm.tm_mon, 0);
  KEXPECT_LE(tm.tm_mon, 11);
  KEXPECT_GE(tm.tm_mday, 1);
  KEXPECT_LE(tm.tm_mday, 31);
  KEXPECT_GE(tm.tm_hour, 0);
  KEXPECT_LE(tm.tm_hour, 23);
  KEXPECT_GE(tm.tm_min, 0);
  KEXPECT_LE(tm.tm_min, 59);
  KEXPECT_GE(tm.tm_sec, 0);
  KEXPECT_LE(tm.tm_sec, 61);

  KTEST_BEGIN("apos_get_time(): bad arguments test");
  KEXPECT_SIGNAL(SIGSEGV, apos_get_time(NULL));
  KEXPECT_SIGNAL(SIGSEGV, apos_get_time((struct apos_tm*)0x1cfff));
  KEXPECT_SIGNAL(SIGSEGV, apos_get_time((struct apos_tm*)0xc1000000));
}

static void termios_test(void) {
  KTEST_SUITE_BEGIN("termios tests");
  KTEST_BEGIN("tcgetattr()/tcsetattr(): basic test");
  struct termios t;
  memset(&t, 0, sizeof(t));

  int fd = open("/dev/tty0", O_RDWR);
  KEXPECT_GE(fd, 0);

  KEXPECT_EQ(0, tcgetattr(fd, &t));
  const tcflag_t kAllIFlag = BRKINT | ICRNL | IGNBRK | IGNCR | IGNPAR | INLCR |
                             INPCK | ISTRIP | IXANY | IXOFF | IXON | PARMRK;
  const tcflag_t kAllOFlag =
      OPOST | ONLCR | OCRNL | ONOCR | ONLRET | OFDEL | OFILL | NLDLY | NL0 |
      NL1 | CRDLY | CR0 | CR1 | CR2 | CR3 | TABDLY | TAB0 | TAB1 | TAB2 | TAB3 |
      BSDLY | BS0 | BS1 | VTDLY | VT0 | VT1 | FFDLY | FF0 | FF1;
  const tcflag_t kAllCFlag =
      CSIZE | CSTOPB | CREAD | PARENB | PARODD | HUPCL | CLOCAL;
  const tcflag_t kAllLFlag =
      ECHO | ECHOE | ECHOK | ECHONL | ICANON | IEXTEN | ISIG | NOFLSH | TOSTOP;

  KEXPECT_EQ(0, t.c_iflag & ~kAllIFlag);
  KEXPECT_EQ(0, t.c_oflag & ~kAllOFlag);
  KEXPECT_EQ(0, t.c_cflag & ~kAllCFlag);
  KEXPECT_EQ(0, t.c_lflag & ~kAllLFlag);

  const struct termios orig_t = t;
  t.c_lflag ^= ECHO;
  KEXPECT_EQ(0, tcsetattr(fd, TCSANOW, &t));
  memset(&t, 0, sizeof(t));
  KEXPECT_EQ(0, tcgetattr(fd, &t));
  KEXPECT_EQ(orig_t.c_iflag, t.c_iflag);
  KEXPECT_EQ(orig_t.c_oflag, t.c_oflag);
  KEXPECT_EQ(orig_t.c_cflag, t.c_cflag);
  KEXPECT_NE(orig_t.c_lflag, t.c_lflag);
  KEXPECT_EQ(orig_t.c_lflag, t.c_lflag ^ ECHO);
  t.c_lflag = orig_t.c_lflag;
  KEXPECT_EQ(0, tcsetattr(fd, TCSANOW, &t));

  KTEST_BEGIN("tcgetattr()/tcsetattr(): bad arguments test");
  KEXPECT_EQ(-1, tcgetattr(-5, &t));
  KEXPECT_EQ(EBADF, errno);
  KEXPECT_SIGNAL(SIGSEGV, tcgetattr(fd, NULL));
  KEXPECT_SIGNAL(SIGSEGV, tcgetattr(fd, (struct termios*)0x1fff));
  KEXPECT_SIGNAL(SIGSEGV, tcgetattr(fd, (struct termios*)0xc1000000));
  KEXPECT_EQ(-1, tcsetattr(-5, TCSANOW, &t));
  KEXPECT_EQ(EBADF, errno);
  KEXPECT_EQ(-1, tcsetattr(fd, 55, &t));
  KEXPECT_EQ(EINVAL, errno);
  KEXPECT_SIGNAL(SIGSEGV, tcsetattr(fd, TCSANOW, NULL));
  KEXPECT_SIGNAL(SIGSEGV, tcsetattr(fd, TCSANOW, (struct termios*)0x1fff));
  KEXPECT_SIGNAL(SIGSEGV, tcsetattr(fd, TCSANOW, (struct termios*)0xc1000000));

  KEXPECT_EQ(0, close(fd));
}

static void rlimit_test(void) {
  KTEST_SUITE_BEGIN("get/setrlimit() tests");

  KTEST_BEGIN("get/setrlimit() basic test");
  struct rlimit rl = {0, 0};
  KEXPECT_EQ(0, getrlimit(RLIMIT_NOFILE, &rl));
  KEXPECT_GE(rl.rlim_max, rl.rlim_cur);
  const struct rlimit orig_rl = rl;
  rl.rlim_cur = 5;

  KEXPECT_EQ(0, setrlimit(RLIMIT_NOFILE, &rl));
  rl.rlim_max = rl.rlim_cur = 0;
  KEXPECT_EQ(0, getrlimit(RLIMIT_NOFILE, &rl));
  KEXPECT_EQ(5, rl.rlim_cur);
  KEXPECT_EQ(orig_rl.rlim_max, rl.rlim_max);

  KEXPECT_EQ(0, setrlimit(RLIMIT_NOFILE, &orig_rl));
  // We should be able to open a file now.
  int fds[2];
  KEXPECT_EQ(0, pipe(fds));
  KEXPECT_EQ(0, close(fds[0]));
  KEXPECT_EQ(0, close(fds[1]));

  KTEST_BEGIN("get/setrlimit() bad argument test");
  KEXPECT_EQ(-1, getrlimit(-5, &rl));
  KEXPECT_EQ(EINVAL, errno);
  KEXPECT_EQ(-1, getrlimit(100, &rl));
  KEXPECT_EQ(EINVAL, errno);
  KEXPECT_SIGNAL(SIGSEGV, getrlimit(RLIMIT_NOFILE, NULL));
  KEXPECT_SIGNAL(SIGSEGV, getrlimit(100, (struct rlimit*)0x1fff));

  KEXPECT_EQ(-1, setrlimit(-5, &rl));
  KEXPECT_EQ(EINVAL, errno);
  KEXPECT_EQ(-1, setrlimit(100, &rl));
  KEXPECT_EQ(EINVAL, errno);
  KEXPECT_SIGNAL(SIGSEGV, setrlimit(RLIMIT_NOFILE, NULL));
  KEXPECT_SIGNAL(SIGSEGV, setrlimit(100, (struct rlimit*)0x1fff));
}

void misc_syscall_test(void) {
  apos_get_time_test();
  termios_test();
  rlimit_test();
}
