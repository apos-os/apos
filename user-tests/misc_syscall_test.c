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
#include <apos/test.h>
#include <apos/time_types.h>
#include <fcntl.h>
#include <sys/resource.h>
#include <sys/select.h>
#include <termios.h>
#include <unistd.h>

#include "ktest.h"
#include "user-tests/arch.h"

static void test_syscall_test(void) {
  KTEST_SUITE_BEGIN("syscall_test() test");
  KTEST_BEGIN("syscall_test(): basic test");

#if ARCH_IS_64_BIT
  KEXPECT_EQ(
      0xffffffff85daa734,
      syscall_test(0xffffffff12345678, 0xffffffff12345679, 0xffffffff1234567a,
                   0xffffffff1234567b, 0xffffffff1234567c, 0xffffffff1234567d));
#else
  KEXPECT_EQ(0x41aa6204, syscall_test(0x12345678, 0x12345679, 0x1234567a,
                                      0x1234567b, 0x1234567c, 0x1234567d));
#endif
}

static void apos_get_time_test(void) {
  KTEST_SUITE_BEGIN("apos_get_time() test");
  KTEST_BEGIN("apos_get_time(): basic test");
  struct apos_tm tm;
  memset(&tm, 0, sizeof(tm));

#if defined(ARCH_X86)
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
#else
  KEXPECT_ERRNO(ENOTSUP, apos_get_time(&tm));
#endif

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
  rl.rlim_cur = 15;

  KEXPECT_EQ(0, setrlimit(RLIMIT_NOFILE, &rl));
  rl.rlim_max = rl.rlim_cur = 0;
  KEXPECT_EQ(0, getrlimit(RLIMIT_NOFILE, &rl));
  KEXPECT_EQ(15, rl.rlim_cur);
  KEXPECT_EQ(orig_rl.rlim_max, rl.rlim_max);

  // We should be able to dup2() to a low numbered fd, but not a high one.
  int fds[2];
  KEXPECT_EQ(0, pipe(fds));
  KEXPECT_EQ(14, dup2(fds[0], 14));
  KEXPECT_ERRNO(EMFILE, dup2(fds[0], 15));
  KEXPECT_ERRNO(EMFILE, dup2(0, 16));
  KEXPECT_ERRNO(EMFILE, dup2(0, 30));
  KEXPECT_EQ(0, close(14));
  KEXPECT_EQ(0, close(fds[0]));
  KEXPECT_EQ(0, close(fds[1]));

  // We should be able to round-trip RLIM_INFINITY.
  rl.rlim_max = rl.rlim_cur = RLIM_INFINITY;
  KEXPECT_EQ(0, setrlimit(RLIMIT_NOFILE, &rl));
  rl.rlim_max = rl.rlim_cur = 0;
  KEXPECT_EQ(0, getrlimit(RLIMIT_NOFILE, &rl));
  KEXPECT_EQ(RLIM_INFINITY, rl.rlim_cur);
  KEXPECT_EQ(RLIM_INFINITY, rl.rlim_max);

  KEXPECT_EQ(0, pipe(fds));
  KEXPECT_EQ(14, dup2(fds[0], 14));
  KEXPECT_EQ(15, dup2(fds[0], 15));
  KEXPECT_EQ(31, dup2(fds[0], 31));
  KEXPECT_EQ(0, close(14));
  KEXPECT_EQ(0, close(15));
  KEXPECT_EQ(0, close(31));
  KEXPECT_EQ(0, close(fds[0]));
  KEXPECT_EQ(0, close(fds[1]));

  KEXPECT_EQ(0, setrlimit(RLIMIT_NOFILE, &orig_rl));
  // We should be able to open a file now.
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

// Test the poll()-wrapping version of select() included in the APOS newlib
// implementation.
static void select_test(void) {
  KTEST_SUITE_BEGIN("select() tests");

  KTEST_BEGIN("select() basic test");
  int pfds[2];
  KEXPECT_EQ(0, pipe(pfds));
  const int pfd1 = 24;
  const int pfd2 = 30;
  KEXPECT_EQ(pfd1, dup2(pfds[0], pfd1));
  KEXPECT_EQ(pfd2, dup2(pfds[1], pfd2));
  KEXPECT_EQ(0, close(pfds[0]));
  KEXPECT_EQ(0, close(pfds[1]));

  fd_set allfds;
  fd_set rset, wset, eset;
  FD_ZERO(&allfds);
  FD_ZERO(&rset);
  FD_ZERO(&wset);
  FD_ZERO(&eset);
  FD_SET(pfd1, &allfds);
  FD_SET(pfd2, &allfds);
  struct timeval tv;
  tv.tv_sec = 0;
  tv.tv_usec = 0;
  KEXPECT_EQ(0, select(FD_SETSIZE, &rset, &wset, &eset, &tv));
  KEXPECT_EQ(0, select(FD_SETSIZE, NULL, NULL, NULL, &tv));

  FD_COPY(&allfds, &wset);
  KEXPECT_EQ(1, select(FD_SETSIZE, &rset, &wset, &eset, &tv));
  KEXPECT_FALSE(FD_ISSET(pfd1, &wset));
  KEXPECT_TRUE(FD_ISSET(pfd2, &wset));
  KEXPECT_EQ(1, select(FD_SETSIZE, &rset, &wset, &eset, NULL));
  KEXPECT_FALSE(FD_ISSET(pfd1, &wset));
  KEXPECT_TRUE(FD_ISSET(pfd2, &wset));
  KEXPECT_FALSE(FD_ISSET(pfd1, &rset));
  KEXPECT_FALSE(FD_ISSET(pfd1, &eset));

  FD_COPY(&allfds, &wset);
  KEXPECT_EQ(0, select(pfd1 + 1, &rset, &wset, &eset, &tv));
  KEXPECT_FALSE(FD_ISSET(pfd1, &wset));
  KEXPECT_FALSE(FD_ISSET(pfd2, &wset));


  KTEST_BEGIN("select() readfds test");
  FD_COPY(&allfds, &rset);
  FD_COPY(&allfds, &wset);
  FD_COPY(&allfds, &eset);
  KEXPECT_EQ(3, write(pfd2, "abc", 3));
  KEXPECT_EQ(2, select(FD_SETSIZE, &rset, &wset, &eset, &tv));
  KEXPECT_EQ(2, select(FD_SETSIZE, &rset, &wset, &eset, NULL));
  KEXPECT_FALSE(FD_ISSET(pfd1, &wset));
  KEXPECT_TRUE(FD_ISSET(pfd2, &wset));
  KEXPECT_TRUE(FD_ISSET(pfd1, &rset));
  KEXPECT_FALSE(FD_ISSET(pfd2, &rset));
  KEXPECT_FALSE(FD_ISSET(pfd1, &eset));
  KEXPECT_FALSE(FD_ISSET(pfd2, &eset));
  KEXPECT_EQ(1, select(FD_SETSIZE, &rset, NULL, NULL, NULL));

  FD_COPY(&allfds, &rset);
  FD_COPY(&allfds, &wset);
  FD_COPY(&allfds, &eset);
  KEXPECT_EQ(1, select(pfd1 + 1, &rset, &wset, &eset, NULL));
  KEXPECT_TRUE(FD_ISSET(pfd1, &rset));
  KEXPECT_FALSE(FD_ISSET(pfd2, &rset));

  KTEST_BEGIN("select() exceptfds test");
  FD_COPY(&allfds, &rset);
  FD_COPY(&allfds, &wset);
  FD_ZERO(&eset);

  KEXPECT_EQ(0, select(FD_SETSIZE, NULL, NULL, &eset, &tv));
  KEXPECT_FALSE(FD_ISSET(pfd1, &eset));
  KEXPECT_FALSE(FD_ISSET(pfd2, &eset));

  FD_COPY(&allfds, &eset);
  KEXPECT_EQ(0, select(FD_SETSIZE, NULL, NULL, &eset, &tv));
  KEXPECT_FALSE(FD_ISSET(pfd1, &eset));
  KEXPECT_FALSE(FD_ISSET(pfd2, &eset));

  KEXPECT_EQ(0, close(pfd1));
  // If we pass both, we should get EBADF.
  FD_COPY(&allfds, &rset);
  KEXPECT_ERRNO(EBADF, select(FD_SETSIZE, &rset, NULL, NULL, &tv));
  FD_COPY(&allfds, &wset);
  KEXPECT_ERRNO(EBADF, select(FD_SETSIZE, NULL, &wset, NULL, &tv));
  FD_COPY(&allfds, &eset);
  KEXPECT_ERRNO(EBADF, select(FD_SETSIZE, NULL, NULL, &eset, &tv));
  FD_COPY(&allfds, &rset);
  FD_COPY(&allfds, &wset);
  FD_COPY(&allfds, &eset);
  KEXPECT_ERRNO(EBADF, select(FD_SETSIZE, &rset, &wset, &eset, &tv));

  // Test again with just pfd2 set.
  FD_ZERO(&eset);
  FD_SET(pfd2, &eset);
  KEXPECT_EQ(1, select(FD_SETSIZE, NULL, NULL, &eset, &tv));
  KEXPECT_FALSE(FD_ISSET(pfd1, &eset));
  KEXPECT_TRUE(FD_ISSET(pfd2, &eset));

  // Test again with pfd2 set in rset, but _not_ eset.
  FD_ZERO(&eset);
  FD_ZERO(&rset);
  FD_SET(pfd2, &rset);
  KEXPECT_EQ(1, select(FD_SETSIZE, &rset, NULL, &eset, &tv));
  KEXPECT_FALSE(FD_ISSET(pfd1, &rset));
  KEXPECT_FALSE(FD_ISSET(pfd2, &rset));
  KEXPECT_FALSE(FD_ISSET(pfd1, &eset));
  KEXPECT_FALSE(FD_ISSET(pfd2, &eset));

  KEXPECT_EQ(0, select(0, &rset, NULL, NULL, &tv));
  KEXPECT_ERRNO(EINVAL, select(FD_SETSIZE + 1, &rset, NULL, NULL, &tv));
  KEXPECT_ERRNO(EINVAL, select(-1, &rset, NULL, NULL, &tv));

  KEXPECT_EQ(0, close(pfd2));
}

void misc_syscall_test(void) {
  test_syscall_test();
  apos_get_time_test();
  termios_test();
  rlimit_test();
  select_test();
}
