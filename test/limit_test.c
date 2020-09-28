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

#include "common/errno.h"
#include "memory/mmap.h"
#include "proc/fork.h"
#include "proc/limit.h"
#include "proc/signal/signal.h"
#include "proc/user.h"
#include "proc/wait.h"
#include "test/kernel_tests.h"
#include "test/ktest.h"
#include "vfs/vfs.h"
#include "vfs/vfs_test_util.h"

static int sig_is_pending(int sig) {
  ksigset_t pending = proc_pending_signals(proc_current());
  return ksigismember(&pending, sig);
}

static void basic_test(void* arg) {
  KTEST_BEGIN("getrlimit(): initial values");
  for (int i = 0; i < APOS_RLIMIT_NUM_RESOURCES; ++i) {
    struct apos_rlimit lim = {0, 0};
    KEXPECT_EQ(0, proc_getrlimit(i, &lim));
    KEXPECT_EQ(APOS_RLIM_INFINITY, lim.rlim_cur);
    KEXPECT_EQ(APOS_RLIM_INFINITY, lim.rlim_max);
  }

  KTEST_BEGIN("getrlimit(): invalid resource");
  struct apos_rlimit lim;
  KEXPECT_EQ(-EINVAL, proc_getrlimit(-1, &lim));
  KEXPECT_EQ(-EINVAL, proc_getrlimit(-10, &lim));
  KEXPECT_EQ(-EINVAL, proc_getrlimit(APOS_RLIMIT_NUM_RESOURCES, &lim));

  KTEST_BEGIN("setrlimit(): basic set");
  lim.rlim_cur = 100;
  lim.rlim_max = 200;
  KEXPECT_EQ(0, proc_setrlimit(APOS_RLIMIT_AS, &lim));
  lim.rlim_cur = lim.rlim_max = 0;
  KEXPECT_EQ(0, proc_getrlimit(APOS_RLIMIT_AS, &lim));
  KEXPECT_EQ(100, lim.rlim_cur);
  KEXPECT_EQ(200, lim.rlim_max);

  KTEST_BEGIN("setrlimit(): invalid resource");
  KEXPECT_EQ(-EINVAL, proc_setrlimit(-1, &lim));
  KEXPECT_EQ(-EINVAL, proc_setrlimit(-10, &lim));
  KEXPECT_EQ(-EINVAL, proc_setrlimit(APOS_RLIMIT_NUM_RESOURCES, &lim));

  KTEST_BEGIN("setrlimit(): cur > max");
  lim.rlim_cur = 200;
  lim.rlim_max = 200;
  KEXPECT_EQ(0, proc_setrlimit(APOS_RLIMIT_AS, &lim));
  lim.rlim_cur = 301;
  lim.rlim_max = 300;
  KEXPECT_EQ(-EINVAL, proc_setrlimit(APOS_RLIMIT_AS, &lim));
  KEXPECT_EQ(0, proc_getrlimit(APOS_RLIMIT_AS, &lim));
  KEXPECT_EQ(200, lim.rlim_cur);
  KEXPECT_EQ(200, lim.rlim_max);
}

static void fork_test_child(void* arg) {
  struct apos_rlimit lim = {0, 0};
  KEXPECT_EQ(0, proc_getrlimit(APOS_RLIMIT_AS, &lim));
  KEXPECT_EQ(200, lim.rlim_cur);
  KEXPECT_EQ(300, lim.rlim_max);
}

static void limit_fork_test(void* arg) {
  KTEST_BEGIN("limits: propagated in fork()");
  struct apos_rlimit lim = {200, 300};
  KEXPECT_EQ(0, proc_setrlimit(APOS_RLIMIT_AS, &lim));
  kpid_t child = proc_fork(&fork_test_child, NULL);
  KEXPECT_EQ(child, proc_wait(NULL));
}

static void limit_perm_test(void* arg) {
  const int kGroupA = 1, kGroupB = 2, kUserA = 3, kUserB = 4;

  KTEST_BEGIN("setrlimit(): non-root can lower max limit");
  KEXPECT_EQ(0, setregid(kGroupB, kGroupA));
  KEXPECT_EQ(0, setreuid(kUserB, kUserA));

  struct apos_rlimit lim = {200, 300};
  KEXPECT_EQ(0, proc_setrlimit(APOS_RLIMIT_AS, &lim));
  lim.rlim_cur = lim.rlim_max = 0;
  KEXPECT_EQ(0, proc_getrlimit(APOS_RLIMIT_AS, &lim));
  KEXPECT_EQ(200, lim.rlim_cur);
  KEXPECT_EQ(300, lim.rlim_max);


  KTEST_BEGIN("setrlimit(): non-root can raise soft limit");
  lim.rlim_cur = 250;
  lim.rlim_max = 300;
  KEXPECT_EQ(0, proc_setrlimit(APOS_RLIMIT_AS, &lim));
  lim.rlim_cur = lim.rlim_max = 0;
  KEXPECT_EQ(0, proc_getrlimit(APOS_RLIMIT_AS, &lim));
  KEXPECT_EQ(250, lim.rlim_cur);
  KEXPECT_EQ(300, lim.rlim_max);


  KTEST_BEGIN("setrlimit(): non-root can't raise max limit");
  lim.rlim_cur = 220;
  lim.rlim_max = 350;
  KEXPECT_EQ(-EPERM, proc_setrlimit(APOS_RLIMIT_AS, &lim));
  lim.rlim_cur = lim.rlim_max = 0;
  KEXPECT_EQ(0, proc_getrlimit(APOS_RLIMIT_AS, &lim));
  KEXPECT_EQ(250, lim.rlim_cur);
  KEXPECT_EQ(300, lim.rlim_max);
}

static void limit_nofile_test(void* arg) {
  KTEST_BEGIN("setrlimit(): APOS_RLIMIT_NOFILE enforced by vfs_open()");
  const int kNumFds = 10;
  int fds[kNumFds + 1];
  struct apos_rlimit lim = {kNumFds, APOS_RLIM_INFINITY};
  KEXPECT_EQ(0, proc_setrlimit(APOS_RLIMIT_NOFILE, &lim));

  for (int i = 0; i < kNumFds + 1; ++i) {
    fds[i] = vfs_open("_tmp_test_f", VFS_O_RDONLY | VFS_O_CREAT, VFS_S_IRWXU);
    if (fds[i] < 0)
      KEXPECT_EQ(-EMFILE, fds[i]);
    else
      KEXPECT_LT(fds[i], kNumFds);
  }
  KEXPECT_EQ(-EMFILE, vfs_open("_tmp_test_f", VFS_O_RDONLY));
  KEXPECT_EQ(0, vfs_close(fds[3]));
  KEXPECT_EQ(fds[3], vfs_open("_tmp_test_f", VFS_O_RDONLY));
  for (int i = 0; i < kNumFds + 1; ++i) {
    if (fds[i] >= 0) vfs_close(fds[i]);
  }

  KTEST_BEGIN("setrlimit(): RLIMIT_NOFILE enforced by vfs_dup()");
  int initial_fd = vfs_open("_tmp_test_f", VFS_O_RDONLY);
  for (int i = 0; i < kNumFds + 1; ++i) {
    fds[i] = vfs_dup(initial_fd);
    if (fds[i] < 0)
      KEXPECT_EQ(-EMFILE, fds[i]);
    else
      KEXPECT_LT(fds[i], kNumFds);
  }
  KEXPECT_EQ(-EMFILE, vfs_open("_tmp_test_f", VFS_O_RDONLY));
  KEXPECT_EQ(0, vfs_close(fds[3]));
  KEXPECT_EQ(fds[3], vfs_dup(initial_fd));
  for (int i = 0; i < kNumFds + 1; ++i) {
    if (fds[i] >= 0) vfs_close(fds[i]);
  }
  KEXPECT_EQ(0, vfs_close(initial_fd));

  KTEST_BEGIN("setrlimit(): RLIMIT_NOFILE enforced by vfs_dup2()");
  initial_fd = vfs_open("_tmp_test_f", VFS_O_RDONLY);
  KEXPECT_EQ(kNumFds - 1, vfs_dup2(initial_fd, kNumFds - 1));
  KEXPECT_EQ(0, vfs_close(kNumFds - 1));
  KEXPECT_EQ(-EMFILE, vfs_dup2(initial_fd, kNumFds));
  KEXPECT_EQ(-EMFILE, vfs_dup2(initial_fd, kNumFds + 1));
  KEXPECT_EQ(-EMFILE, vfs_dup2(initial_fd, kNumFds + 2));
  KEXPECT_EQ(0, vfs_close(initial_fd));

  KTEST_BEGIN("setrlimit(): handles high RLIMIT_NOFILE values");
  lim.rlim_cur = APOS_RLIM_INFINITY - 1;
  lim.rlim_max = APOS_RLIM_INFINITY;
  KEXPECT_EQ(0, proc_setrlimit(APOS_RLIMIT_NOFILE, &lim));

  int fd = vfs_open("_tmp_test_f", VFS_O_RDONLY | VFS_O_CREAT, VFS_S_IRWXU);
  KEXPECT_GE(fd, 0);
  KEXPECT_EQ(0, vfs_close(fd));

  lim.rlim_cur = (double)APOS_RLIM_INFINITY * 0.75;
  KEXPECT_EQ(0, proc_setrlimit(APOS_RLIMIT_NOFILE, &lim));
  fd = vfs_open("_tmp_test_f", VFS_O_RDONLY | VFS_O_CREAT, VFS_S_IRWXU);
  KEXPECT_GE(fd, 0);
  KEXPECT_EQ(0, vfs_close(fd));

  lim.rlim_cur = (double)APOS_RLIM_INFINITY * 0.5 + 20;
  KEXPECT_EQ(0, proc_setrlimit(APOS_RLIMIT_NOFILE, &lim));
  fd = vfs_open("_tmp_test_f", VFS_O_RDONLY | VFS_O_CREAT, VFS_S_IRWXU);
  KEXPECT_GE(fd, 0);
  KEXPECT_EQ(0, vfs_close(fd));

  lim.rlim_cur = INT_MAX;
  KEXPECT_EQ(0, proc_setrlimit(APOS_RLIMIT_NOFILE, &lim));
  fd = vfs_open("_tmp_test_f", VFS_O_RDONLY | VFS_O_CREAT, VFS_S_IRWXU);
  KEXPECT_GE(fd, 0);
  KEXPECT_EQ(0, vfs_close(fd));

  KEXPECT_EQ(0, vfs_unlink("_tmp_test_f"));
}

static void limit_filesize_test(void* arg) {
  KTEST_BEGIN("setrlimit(): vfs_write()/RLIMIT_FSIZE large file, below limit");
  KEXPECT_EQ(0, vfs_mkdir("_rlim_test", VFS_S_IRWXU));
  int fd = vfs_open("_rlim_test/A", VFS_O_RDWR | VFS_O_CREAT, VFS_S_IRWXU);
  KEXPECT_GE(fd, 0);
  char buf[100];
  kmemset(buf, 'a', 100);
  for (int i = 0; i < 20; ++i)
    KEXPECT_EQ(100, vfs_write(fd, buf, 100));

  struct apos_rlimit lim;
  lim.rlim_cur = 1000;
  lim.rlim_max = APOS_RLIM_INFINITY;
  KEXPECT_EQ(0, proc_setrlimit(APOS_RLIMIT_FSIZE, &lim));
  KEXPECT_EQ(500, vfs_seek(fd, 500, VFS_SEEK_SET));
  KEXPECT_EQ(100, vfs_write(fd, buf, 100));
  KEXPECT_EQ(0, sig_is_pending(SIGXFSZ));


  KTEST_BEGIN("setrlimit(): vfs_write()/RLIMIT_FSIZE large file, across limit");
  lim.rlim_cur = 1000;
  lim.rlim_max = APOS_RLIM_INFINITY;
  KEXPECT_EQ(0, proc_setrlimit(APOS_RLIMIT_FSIZE, &lim));
  KEXPECT_EQ(950, vfs_seek(fd, 950, VFS_SEEK_SET));
  KEXPECT_EQ(100, vfs_write(fd, buf, 100));
  KEXPECT_EQ(0, sig_is_pending(SIGXFSZ));


  KTEST_BEGIN("setrlimit(): vfs_write()/RLIMIT_FSIZE large file, above limit");
  lim.rlim_cur = 1000;
  lim.rlim_max = APOS_RLIM_INFINITY;
  KEXPECT_EQ(0, proc_setrlimit(APOS_RLIMIT_FSIZE, &lim));
  KEXPECT_EQ(1200, vfs_seek(fd, 1200, VFS_SEEK_SET));
  KEXPECT_EQ(100, vfs_write(fd, buf, 100));
  KEXPECT_EQ(0, sig_is_pending(SIGXFSZ));

  KTEST_BEGIN(
      "setrlimit(): vfs_write()/RLIMIT_FSIZE large file, extends above limit");
  lim.rlim_cur = 1000;
  lim.rlim_max = APOS_RLIM_INFINITY;
  KEXPECT_EQ(0, proc_setrlimit(APOS_RLIMIT_FSIZE, &lim));
  KEXPECT_EQ(1950, vfs_seek(fd, 1950, VFS_SEEK_SET));
  KEXPECT_EQ(-EFBIG, vfs_write(fd, buf, 100));
  KEXPECT_EQ(1, sig_is_pending(SIGXFSZ));
  proc_suppress_signal(proc_current(), SIGXFSZ);


  KTEST_BEGIN("setrlimit(): vfs_write()/RLIMIT_FSIZE large file O_APPEND");
  KEXPECT_EQ(0, vfs_close(fd));
  fd = vfs_open("_rlim_test/A", VFS_O_RDWR | VFS_O_APPEND, VFS_S_IRWXU);
  KEXPECT_GE(fd, 0);
  lim.rlim_cur = 1000;
  lim.rlim_max = APOS_RLIM_INFINITY;
  KEXPECT_EQ(0, proc_setrlimit(APOS_RLIMIT_FSIZE, &lim));
  KEXPECT_EQ(0, vfs_seek(fd, 0, VFS_SEEK_SET));
  KEXPECT_EQ(-EFBIG, vfs_write(fd, buf, 100));
  KEXPECT_EQ(1, sig_is_pending(SIGXFSZ));
  proc_suppress_signal(proc_current(), SIGXFSZ);
  KEXPECT_EQ(0, vfs_close(fd));


  KTEST_BEGIN("setrlimit(): vfs_write()/RLIMIT_FSIZE small file, below limit");
  fd = vfs_open("_rlim_test/A", VFS_O_RDWR | VFS_O_CREAT, VFS_S_IRWXU);
  KEXPECT_EQ(0, vfs_ftruncate(fd, 100));
  lim.rlim_cur = 1000;
  lim.rlim_max = APOS_RLIM_INFINITY;
  KEXPECT_EQ(0, proc_setrlimit(APOS_RLIMIT_FSIZE, &lim));
  KEXPECT_EQ(500, vfs_seek(fd, 500, VFS_SEEK_SET));
  KEXPECT_EQ(100, vfs_write(fd, buf, 100));
  KEXPECT_EQ(0, sig_is_pending(SIGXFSZ));


  KTEST_BEGIN(
      "setrlimit(): vfs_write()/RLIMIT_FSIZE small file to exact limit");
  KEXPECT_EQ(0, vfs_ftruncate(fd, 900));
  lim.rlim_cur = 1000;
  lim.rlim_max = APOS_RLIM_INFINITY;
  KEXPECT_EQ(0, proc_setrlimit(APOS_RLIMIT_FSIZE, &lim));
  KEXPECT_EQ(900, vfs_seek(fd, 900, VFS_SEEK_SET));
  KEXPECT_EQ(100, vfs_write(fd, buf, 100));
  KEXPECT_EQ(0, sig_is_pending(SIGXFSZ));


  KTEST_BEGIN("setrlimit(): vfs_write()/RLIMIT_FSIZE small file, across limit");
  KEXPECT_EQ(0, vfs_ftruncate(fd, 950));
  lim.rlim_cur = 1000;
  lim.rlim_max = APOS_RLIM_INFINITY;
  KEXPECT_EQ(0, proc_setrlimit(APOS_RLIMIT_FSIZE, &lim));
  KEXPECT_EQ(975, vfs_seek(fd, 975, VFS_SEEK_SET));
  KEXPECT_EQ(25, vfs_write(fd, buf, 100));
  KEXPECT_EQ(0, sig_is_pending(SIGXFSZ));
  KEXPECT_EQ(-EFBIG, vfs_write(fd, buf, 100));
  KEXPECT_EQ(1, sig_is_pending(SIGXFSZ));
  proc_suppress_signal(proc_current(), SIGXFSZ);


  KTEST_BEGIN("setrlimit(): vfs_write()/RLIMIT_FSIZE small file, above limit");
  KEXPECT_EQ(0, vfs_ftruncate(fd, 950));
  lim.rlim_cur = 1000;
  lim.rlim_max = APOS_RLIM_INFINITY;
  KEXPECT_EQ(0, proc_setrlimit(APOS_RLIMIT_FSIZE, &lim));
  KEXPECT_EQ(1200, vfs_seek(fd, 1200, VFS_SEEK_SET));
  KEXPECT_EQ(-EFBIG, vfs_write(fd, buf, 100));
  KEXPECT_EQ(1, sig_is_pending(SIGXFSZ));
  proc_suppress_signal(proc_current(), SIGXFSZ);


  KTEST_BEGIN("setrlimit(): vfs_write()/RLIMIT_FSIZE small file O_APPEND");
  KEXPECT_EQ(0, vfs_close(fd));
  fd = vfs_open("_rlim_test/A", VFS_O_RDWR | VFS_O_APPEND, VFS_S_IRWXU);
  KEXPECT_GE(fd, 0);
  lim.rlim_cur = 1000;
  lim.rlim_max = APOS_RLIM_INFINITY;
  KEXPECT_EQ(0, proc_setrlimit(APOS_RLIMIT_FSIZE, &lim));
  KEXPECT_EQ(0, vfs_ftruncate(fd, 950));
  KEXPECT_EQ(0, vfs_seek(fd, 0, VFS_SEEK_SET));
  KEXPECT_EQ(50, vfs_write(fd, buf, 100));
  KEXPECT_EQ(-EFBIG, vfs_write(fd, buf, 100));
  KEXPECT_EQ(1, sig_is_pending(SIGXFSZ));
  proc_suppress_signal(proc_current(), SIGXFSZ);
  KEXPECT_EQ(0, vfs_close(fd));


  KTEST_BEGIN("setrlimit(): vfs_ftruncate()/RLIMIT_FSIZE under limit");
  fd = vfs_open("_rlim_test/A", VFS_O_RDWR | VFS_O_APPEND, VFS_S_IRWXU);
  KEXPECT_GE(fd, 0);
  lim.rlim_cur = 1000;
  lim.rlim_max = APOS_RLIM_INFINITY;
  KEXPECT_EQ(0, proc_setrlimit(APOS_RLIMIT_FSIZE, &lim));
  KEXPECT_EQ(0, vfs_ftruncate(fd, 0));
  KEXPECT_EQ(0, vfs_ftruncate(fd, 50));
  KEXPECT_EQ(0, vfs_ftruncate(fd, 950));
  KEXPECT_EQ(0, vfs_ftruncate(fd, 1000));


  KTEST_BEGIN("setrlimit(): vfs_ftruncate()/RLIMIT_FSIZE over limit");
  lim.rlim_cur = 1000;
  lim.rlim_max = APOS_RLIM_INFINITY;
  KEXPECT_EQ(0, proc_setrlimit(APOS_RLIMIT_FSIZE, &lim));
  KEXPECT_EQ(-EFBIG, vfs_ftruncate(fd, 1100));
  KEXPECT_EQ(1, sig_is_pending(SIGXFSZ));
  proc_suppress_signal(proc_current(), SIGXFSZ);


  KTEST_BEGIN(
      "setrlimit(): vfs_ftruncate()/RLIMIT_FSIZE reduce size across limit");
  lim.rlim_cur = 2000;
  lim.rlim_max = APOS_RLIM_INFINITY;
  KEXPECT_EQ(0, proc_setrlimit(APOS_RLIMIT_FSIZE, &lim));
  KEXPECT_EQ(0, vfs_ftruncate(fd, 1100));
  lim.rlim_cur = 1000;
  KEXPECT_EQ(0, proc_setrlimit(APOS_RLIMIT_FSIZE, &lim));
  KEXPECT_EQ(0, vfs_ftruncate(fd, 900));
  KEXPECT_EQ(0, sig_is_pending(SIGXFSZ));


  KTEST_BEGIN(
      "setrlimit(): vfs_ftruncate()/RLIMIT_FSIZE reduce size over limit");
  lim.rlim_cur = 2000;
  lim.rlim_max = APOS_RLIM_INFINITY;
  KEXPECT_EQ(0, proc_setrlimit(APOS_RLIMIT_FSIZE, &lim));
  KEXPECT_EQ(0, vfs_ftruncate(fd, 1100));
  lim.rlim_cur = 1000;
  KEXPECT_EQ(0, proc_setrlimit(APOS_RLIMIT_FSIZE, &lim));
  KEXPECT_EQ(-EFBIG, vfs_ftruncate(fd, 1050));
  KEXPECT_EQ(1, sig_is_pending(SIGXFSZ));
  proc_suppress_signal(proc_current(), SIGXFSZ);


  KTEST_BEGIN(
      "setrlimit(): vfs_ftruncate()/RLIMIT_FSIZE increase size over limit");
  KEXPECT_EQ(-EFBIG, vfs_ftruncate(fd, 1200));
  KEXPECT_EQ(1, sig_is_pending(SIGXFSZ));
  proc_suppress_signal(proc_current(), SIGXFSZ);
  KEXPECT_EQ(0, vfs_close(fd));


  KTEST_BEGIN("setrlimit(): vfs_truncate()/RLIMIT_FSIZE under limit");
  lim.rlim_cur = 1000;
  lim.rlim_max = APOS_RLIM_INFINITY;
  KEXPECT_EQ(0, proc_setrlimit(APOS_RLIMIT_FSIZE, &lim));
  KEXPECT_EQ(0, vfs_truncate("_rlim_test/A", 0));
  KEXPECT_EQ(0, vfs_truncate("_rlim_test/A", 50));
  KEXPECT_EQ(0, vfs_truncate("_rlim_test/A", 950));
  KEXPECT_EQ(0, vfs_truncate("_rlim_test/A", 1000));


  KTEST_BEGIN("setrlimit(): vfs_truncate()/RLIMIT_FSIZE over limit");
  lim.rlim_cur = 1000;
  lim.rlim_max = APOS_RLIM_INFINITY;
  KEXPECT_EQ(0, proc_setrlimit(APOS_RLIMIT_FSIZE, &lim));
  KEXPECT_EQ(-EFBIG, vfs_truncate("_rlim_test/A", 1100));
  KEXPECT_EQ(1, sig_is_pending(SIGXFSZ));
  proc_suppress_signal(proc_current(), SIGXFSZ);


  KTEST_BEGIN(
      "setrlimit(): vfs_truncate()/RLIMIT_FSIZE reduce size across limit");
  lim.rlim_cur = 2000;
  lim.rlim_max = APOS_RLIM_INFINITY;
  KEXPECT_EQ(0, proc_setrlimit(APOS_RLIMIT_FSIZE, &lim));
  KEXPECT_EQ(0, vfs_truncate("_rlim_test/A", 1100));
  lim.rlim_cur = 1000;
  KEXPECT_EQ(0, proc_setrlimit(APOS_RLIMIT_FSIZE, &lim));
  KEXPECT_EQ(0, vfs_truncate("_rlim_test/A", 900));
  KEXPECT_EQ(0, sig_is_pending(SIGXFSZ));


  KTEST_BEGIN(
      "setrlimit(): vfs_truncate()/RLIMIT_FSIZE reduce size over limit");
  lim.rlim_cur = 2000;
  lim.rlim_max = APOS_RLIM_INFINITY;
  KEXPECT_EQ(0, proc_setrlimit(APOS_RLIMIT_FSIZE, &lim));
  KEXPECT_EQ(0, vfs_truncate("_rlim_test/A", 1100));
  lim.rlim_cur = 1000;
  KEXPECT_EQ(0, proc_setrlimit(APOS_RLIMIT_FSIZE, &lim));
  KEXPECT_EQ(-EFBIG, vfs_truncate("_rlim_test/A", 1050));
  KEXPECT_EQ(1, sig_is_pending(SIGXFSZ));
  proc_suppress_signal(proc_current(), SIGXFSZ);


  KTEST_BEGIN(
      "setrlimit(): vfs_truncate()/RLIMIT_FSIZE increase size over limit");
  KEXPECT_EQ(-EFBIG, vfs_truncate("_rlim_test/A", 1200));
  KEXPECT_EQ(1, sig_is_pending(SIGXFSZ));
  proc_suppress_signal(proc_current(), SIGXFSZ);


  KEXPECT_EQ(0, vfs_unlink("_rlim_test/A"));
  KEXPECT_EQ(0, vfs_rmdir("_rlim_test"));
}

static void limit_as_test(void* arg) {
  KTEST_BEGIN("setrlimit(): mmap() obeys RLIMIT_AS");
  struct apos_rlimit lim;
  lim.rlim_cur = 10 * PAGE_SIZE;
  lim.rlim_max = APOS_RLIM_INFINITY;
  KEXPECT_EQ(0, proc_setrlimit(APOS_RLIMIT_AS, &lim));

  void* mappings[4];
  KEXPECT_EQ(0, do_mmap(0x0, 5 * PAGE_SIZE, PROT_ALL,
                        KMAP_SHARED | KMAP_ANONYMOUS, -1, 0, &mappings[0]));
  KEXPECT_EQ(0, do_mmap(0x0, 3 * PAGE_SIZE, PROT_ALL,
                        KMAP_SHARED | KMAP_ANONYMOUS, -1, 0, &mappings[1]));
  KEXPECT_EQ(-ENOMEM, do_mmap(0x0, 3 * PAGE_SIZE, PROT_ALL,
                              KMAP_SHARED | KMAP_ANONYMOUS, -1, 0, &mappings[2]));
  KEXPECT_EQ(0, do_mmap(0x0, 2 * PAGE_SIZE, PROT_ALL,
                        KMAP_SHARED | KMAP_ANONYMOUS, -1, 0, &mappings[2]));
  KEXPECT_EQ(-ENOMEM, do_mmap(0x0, PAGE_SIZE, PROT_ALL,
                              KMAP_SHARED | KMAP_ANONYMOUS, -1, 0, &mappings[2]));

  KEXPECT_EQ(
      0, do_munmap((void*)((addr_t)mappings[0] + PAGE_SIZE), 2 * PAGE_SIZE));
  KEXPECT_EQ(-ENOMEM, do_mmap(0x0, 3 * PAGE_SIZE, PROT_ALL,
                              KMAP_SHARED | KMAP_ANONYMOUS, -1, 0, &mappings[3]));
  KEXPECT_EQ(0, do_mmap(0x0, 2 * PAGE_SIZE, PROT_ALL,
                        KMAP_SHARED | KMAP_ANONYMOUS, -1, 0, &mappings[3]));
  KEXPECT_EQ(-ENOMEM, do_mmap(0x0, PAGE_SIZE, PROT_ALL,
                              KMAP_SHARED | KMAP_ANONYMOUS, -1, 0, &mappings[3]));

  KEXPECT_EQ(0, do_munmap(mappings[0], PAGE_SIZE));
  KEXPECT_EQ(0, do_munmap((void*)((addr_t)mappings[0] + 3 * PAGE_SIZE),
                          2 * PAGE_SIZE));
  KEXPECT_EQ(0, do_munmap(mappings[1], 3 * PAGE_SIZE));
  KEXPECT_EQ(0, do_munmap(mappings[2], 2 * PAGE_SIZE));
  KEXPECT_EQ(0, do_munmap(mappings[3], 2 * PAGE_SIZE));
}

void limit_test(void) {
  KTEST_SUITE_BEGIN("process limit tests");
  const int initial_cache_size = vfs_cache_size();

  KEXPECT_GE(proc_fork(&basic_test, NULL), 0);
  KEXPECT_GE(proc_wait(NULL), 0);

  KEXPECT_GE(proc_fork(&limit_fork_test, NULL), 0);
  KEXPECT_GE(proc_wait(NULL), 0);

  KEXPECT_GE(proc_fork(&limit_perm_test, NULL), 0);
  KEXPECT_GE(proc_wait(NULL), 0);

  KEXPECT_GE(proc_fork(&limit_nofile_test, NULL), 0);
  KEXPECT_GE(proc_wait(NULL), 0);

  KEXPECT_GE(proc_fork(&limit_filesize_test, NULL), 0);
  KEXPECT_GE(proc_wait(NULL), 0);

  KEXPECT_GE(proc_fork(&limit_as_test, NULL), 0);
  KEXPECT_GE(proc_wait(NULL), 0);

  KTEST_BEGIN("vfs: vnode leak verification");
  KEXPECT_EQ(initial_cache_size, vfs_cache_size());
}
