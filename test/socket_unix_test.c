// Copyright 2017 Andrew Oates.  All Rights Reserved.
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

#include "test/kernel_tests.h"

#include "memory/kmalloc.h"
#include "net/socket/socket.h"
#include "proc/fork.h"
#include "proc/umask.h"
#include "proc/user.h"
#include "proc/wait.h"
#include "test/ktest.h"
#include "test/vfs_test_util.h"
#include "user/include/apos/errors.h"
#include "user/include/apos/net/socket/unix.h"
#include "vfs/vfs.h"

static void create_test(void) {
  KTEST_BEGIN("net_socket_create(AF_UNIX): basic creation");
  socket_t* sock = NULL;
  KEXPECT_EQ(0, net_socket_create(AF_UNIX, SOCK_STREAM, 0, &sock));
  KEXPECT_NE(NULL, sock);
  KEXPECT_EQ(AF_UNIX, sock->s_domain);
  KEXPECT_EQ(SOCK_STREAM, sock->s_type);
  KEXPECT_EQ(0, sock->s_protocol);
  kfree(sock);

  KTEST_BEGIN("net_socket_create(AF_UNIX): bad type");
  sock = NULL;
  KEXPECT_EQ(-EPROTOTYPE, net_socket_create(AF_UNIX, -1, 0, &sock));
  KEXPECT_EQ(NULL, sock);
  KEXPECT_EQ(-EPROTOTYPE, net_socket_create(AF_UNIX, 5, 0, &sock));
  KEXPECT_EQ(NULL, sock);
  // TODO(aoates): test SOCK_DGRAM, etc when they're defined.

  KTEST_BEGIN("net_socket_create(AF_UNIX): bad protocol");
  KEXPECT_EQ(-EPROTONOSUPPORT,
             net_socket_create(AF_UNIX, SOCK_STREAM, -1, &sock));
  KEXPECT_EQ(NULL, sock);
  KEXPECT_EQ(-EPROTONOSUPPORT,
             net_socket_create(AF_UNIX, SOCK_STREAM, 1, &sock));
  KEXPECT_EQ(NULL, sock);

  KTEST_BEGIN("net_socket(AF_UNIX): basic creation");
  int fd = net_socket(AF_UNIX, SOCK_STREAM, 0);
  KEXPECT_GE(fd, 0);

  KTEST_BEGIN("net_socket(AF_UNIX): fstat() on open AF_UNIX socket");
  apos_stat_t stat;
  KEXPECT_EQ(0, vfs_fstat(fd, &stat));
  KEXPECT_EQ(1, VFS_S_ISSOCK(stat.st_mode));
  KEXPECT_EQ(0, VFS_S_ISSOCK(stat.st_size));
  KEXPECT_EQ(0, vfs_close(fd));

  KTEST_BEGIN("net_socket(AF_UNIX): bad type");
  KEXPECT_EQ(-EPROTOTYPE, net_socket(AF_UNIX, -1, 0));
  KEXPECT_EQ(-EPROTOTYPE, net_socket(AF_UNIX, 5, 0));
  // TODO(aoates): test SOCK_DGRAM, etc when they're defined.

  KTEST_BEGIN("net_socket(AF_UNIX): bad protocol");
  KEXPECT_EQ(-EPROTONOSUPPORT, net_socket(AF_UNIX, SOCK_STREAM, -1));
  KEXPECT_EQ(-EPROTONOSUPPORT, net_socket(AF_UNIX, SOCK_STREAM, 1));

  // TODO(aoates): test failures in net_socket().
}

static void do_bind_mode_test(void* arg) {
  const int kUserA = 1;
  const int kUserB = 2;
  const int kGroupA = 4;
  const int kGroupB = 5;

  KTEST_BEGIN("net_bind(AF_UNIX): bind in non-writable directory");
  KEXPECT_EQ(0, setregid(kGroupB, kGroupA));
  KEXPECT_EQ(0, setreuid(kUserB, kUserA));

  struct sockaddr_un addr;
  addr.sun_family = AF_UNIX;
  kstrcpy(addr.sun_path, "_socket_dir/sock");

  int sock = net_socket(AF_UNIX, SOCK_STREAM, 0);
  KEXPECT_GE(sock, 0);

  KEXPECT_EQ(0, vfs_mkdir("_socket_dir", VFS_S_IRUSR | VFS_S_IXUSR));
  KEXPECT_EQ(-EACCES, net_bind(sock, (struct sockaddr*)&addr, sizeof(addr)));
  KEXPECT_EQ(0, vfs_rmdir("_socket_dir"));

  KTEST_BEGIN("net_bind(AF_UNIX): bind in non-executable directory");
  KEXPECT_EQ(0, vfs_mkdir("_socket_dir", VFS_S_IRUSR | VFS_S_IWUSR));
  KEXPECT_EQ(-EACCES, net_bind(sock, (struct sockaddr*)&addr, sizeof(addr)));
  KEXPECT_EQ(0, vfs_rmdir("_socket_dir"));
}

static void bind_test(void) {
  const char kPath[] = "_socket_bind";

  KTEST_BEGIN("net_bind(AF_UNIX): basic bind test");
  struct sockaddr_un addr;
  addr.sun_family = AF_UNIX;
  kstrcpy(addr.sun_path, kPath);

  int sock = net_socket(AF_UNIX, SOCK_STREAM, 0);
  KEXPECT_GE(sock, 0);
  KEXPECT_EQ(0, net_bind(sock, (struct sockaddr*)&addr, sizeof(addr)));

  apos_stat_t stat;
  KEXPECT_EQ(0, vfs_stat(kPath, &stat));
  KEXPECT_EQ(1, VFS_S_ISSOCK(stat.st_mode));
  int ino = stat.st_ino;

  KEXPECT_EQ(0, vfs_close(sock));
  // The file should still exist after closing the socket.
  KEXPECT_EQ(0, vfs_stat(kPath, &stat));
  KEXPECT_EQ(ino, stat.st_ino);
  KEXPECT_EQ(0, vfs_unlink(kPath));

  KTEST_BEGIN("net_bind(AF_UNIX): bind to wrong address family");
  sock = net_socket(AF_UNIX, SOCK_STREAM, 0);
  KEXPECT_GE(sock, 0);
  addr.sun_family = AF_UNSPEC;
  KEXPECT_EQ(-EAFNOSUPPORT,
             net_bind(sock, (struct sockaddr*)&addr, sizeof(addr)));
  addr.sun_family = -1;
  KEXPECT_EQ(-EAFNOSUPPORT,
             net_bind(sock, (struct sockaddr*)&addr, sizeof(addr)));
  addr.sun_family = 5;
  KEXPECT_EQ(-EAFNOSUPPORT,
             net_bind(sock, (struct sockaddr*)&addr, sizeof(addr)));

  KTEST_BEGIN("net_bind(AF_UNIX): empty path");
  addr.sun_family = AF_UNIX;
  addr.sun_path[0] = '\0';
  KEXPECT_EQ(-ENOENT, net_bind(sock, (struct sockaddr*)&addr, sizeof(addr)));

  KTEST_BEGIN("net_bind(AF_UNIX): path isn't null-terminated");
  addr.sun_family = AF_UNIX;
  kmemset(&addr.sun_path, 'a', sizeof(addr.sun_path));
  KEXPECT_EQ(-ENAMETOOLONG,
             net_bind(sock, (struct sockaddr*)&addr, sizeof(addr)));

  KTEST_BEGIN("net_bind(AF_UNIX): path to invalid directory");
  addr.sun_family = AF_UNIX;
  kstrcpy(addr.sun_path, "bad_dir/socket");
  KEXPECT_EQ(-ENOENT, net_bind(sock, (struct sockaddr*)&addr, sizeof(addr)));

  KTEST_BEGIN("net_bind(AF_UNIX): path over non-directory");
  create_file("_not_dir", "rwxrwxrwx");
  addr.sun_family = AF_UNIX;
  kstrcpy(addr.sun_path, "_not_dir/socket");
  KEXPECT_EQ(-ENOTDIR, net_bind(sock, (struct sockaddr*)&addr, sizeof(addr)));
  KEXPECT_EQ(0, vfs_unlink("_not_dir"));

  KTEST_BEGIN("net_bind(AF_UNIX): binding already-bound socket (same addr)");
  addr.sun_family = AF_UNIX;
  kstrcpy(addr.sun_path, kPath);
  KEXPECT_EQ(0, net_bind(sock, (struct sockaddr*)&addr, sizeof(addr)));
  KEXPECT_EQ(-EINVAL, net_bind(sock, (struct sockaddr*)&addr, sizeof(addr)));

  KTEST_BEGIN("net_bind(AF_UNIX): binding already-bound socket (new addr)");
  kstrcpy(addr.sun_path, "_new_path");
  KEXPECT_EQ(-EINVAL, net_bind(sock, (struct sockaddr*)&addr, sizeof(addr)));
  KEXPECT_EQ(-ENOENT, vfs_stat("_new_path", &stat));
  KEXPECT_EQ(0, vfs_close(sock));
  KEXPECT_EQ(0, vfs_unlink(kPath));

  KTEST_BEGIN("net_bind(AF_UNIX): binding to existing path (regular file)");
  sock = net_socket(AF_UNIX, SOCK_STREAM, 0);
  create_file(kPath, "rwxrwxrwx");
  addr.sun_family = AF_UNIX;
  kstrcpy(addr.sun_path, kPath);
  KEXPECT_EQ(-EADDRINUSE,
             net_bind(sock, (struct sockaddr*)&addr, sizeof(addr)));
  KEXPECT_EQ(0, vfs_unlink(kPath));

  KTEST_BEGIN("net_bind(AF_UNIX): binding to existing path (directory)");
  KEXPECT_EQ(0, vfs_mkdir(kPath, VFS_S_IRWXU));
  KEXPECT_EQ(-EADDRINUSE,
             net_bind(sock, (struct sockaddr*)&addr, sizeof(addr)));
  KEXPECT_EQ(0, vfs_rmdir(kPath));

  KTEST_BEGIN("net_bind(AF_UNIX): binding to existing path (bound socket)");
  KEXPECT_EQ(0, net_bind(sock, (struct sockaddr*)&addr, sizeof(addr)));
  int sock2 = net_socket(AF_UNIX, SOCK_STREAM, 0);
  KEXPECT_EQ(-EADDRINUSE,
             net_bind(sock2, (struct sockaddr*)&addr, sizeof(addr)));

  KTEST_BEGIN("net_bind(AF_UNIX): binding to existing path (unbound socket)");
  KEXPECT_EQ(0, vfs_close(sock));
  sock = -1;
  KEXPECT_EQ(-EADDRINUSE,
             net_bind(sock2, (struct sockaddr*)&addr, sizeof(addr)));
  KEXPECT_EQ(0, vfs_close(sock2));
  sock2 = -1;
  KEXPECT_EQ(0, vfs_unlink(kPath));

  KTEST_BEGIN("net_bind(AF_UNIX): respects umask");
  const mode_t orig_umask = proc_umask(0);
  sock = net_socket(AF_UNIX, SOCK_STREAM, 0);
  addr.sun_family = AF_UNIX;
  kstrcpy(addr.sun_path, kPath);
  KEXPECT_EQ(0, net_bind(sock, (struct sockaddr*)&addr, sizeof(addr)));
  KEXPECT_EQ(0, vfs_stat(kPath, &stat));
  KEXPECT_EQ(VFS_S_IFSOCK | VFS_S_IRWXU | VFS_S_IRWXG | VFS_S_IRWXO,
             stat.st_mode);
  KEXPECT_EQ(0, vfs_close(sock));
  KEXPECT_EQ(0, vfs_unlink(kPath));
  proc_umask(0777);
  sock = net_socket(AF_UNIX, SOCK_STREAM, 0);
  KEXPECT_EQ(0, net_bind(sock, (struct sockaddr*)&addr, sizeof(addr)));
  KEXPECT_EQ(0, vfs_stat(kPath, &stat));
  KEXPECT_EQ(VFS_S_IFSOCK, stat.st_mode);
  KEXPECT_EQ(0, vfs_close(sock));
  KEXPECT_EQ(0, vfs_unlink(kPath));
  proc_umask(orig_umask);

  KTEST_BEGIN("net_bind(AF_UNIX): bind to symlink");
  sock = net_socket(AF_UNIX, SOCK_STREAM, 0);
  addr.sun_family = AF_UNIX;
  kstrcpy(addr.sun_path, kPath);
  KEXPECT_EQ(0, vfs_symlink("_symlink_target", kPath));
  KEXPECT_EQ(0, net_bind(sock, (struct sockaddr*)&addr, sizeof(addr)));
  KEXPECT_EQ(0, vfs_lstat(kPath, &stat));
  KEXPECT_EQ(1, VFS_S_ISLNK(stat.st_mode));
  KEXPECT_EQ(0, vfs_lstat("_symlink_target", &stat));
  KEXPECT_EQ(1, VFS_S_ISSOCK(stat.st_mode));
  KEXPECT_EQ(0, vfs_close(sock));

  KTEST_BEGIN("net_bind(AF_UNIX): bind to symlink (target exists)");
  sock = net_socket(AF_UNIX, SOCK_STREAM, 0);
  KEXPECT_EQ(-EADDRINUSE,
             net_bind(sock, (struct sockaddr*)&addr, sizeof(addr)));
  KEXPECT_EQ(0, vfs_unlink("_symlink_target"));
  KEXPECT_EQ(0, vfs_unlink(kPath));

  KTEST_BEGIN("net_bind(AF_UNIX): bind to symlink (loop)");
  KEXPECT_EQ(0, vfs_symlink(kPath, kPath));
  KEXPECT_EQ(-ELOOP, net_bind(sock, (struct sockaddr*)&addr, sizeof(addr)));
  KEXPECT_EQ(0, vfs_unlink(kPath));
  KEXPECT_EQ(0, vfs_close(sock));

  KTEST_BEGIN("net_bind(AF_UNIX): bind on bad file descriptor");
  KEXPECT_EQ(-EBADF, net_bind(-1, (struct sockaddr*)&addr, sizeof(addr)));
  KEXPECT_EQ(-EBADF, net_bind(100, (struct sockaddr*)&addr, sizeof(addr)));

  KTEST_BEGIN("net_bind(AF_UNIX): bind on non-socket file descriptor");
  int file_fd = vfs_open("_non_socket", VFS_O_RDWR | VFS_O_CREAT, VFS_S_IRWXU);
  KEXPECT_GE(file_fd, 0);
  KEXPECT_EQ(-ENOTSOCK,
             net_bind(file_fd, (struct sockaddr*)&addr, sizeof(addr)));
  KEXPECT_EQ(0, vfs_close(file_fd));
  KEXPECT_EQ(0, vfs_unlink("_non_socket"));

  pid_t child_pid = proc_fork(&do_bind_mode_test, 0x0);
  KEXPECT_GE(child_pid, 0);
  proc_wait(0x0);
}

static void listen_test(void) {
  const char kPath[] = "_socket_path";

  KTEST_BEGIN("net_listen(AF_UNIX): basic listen");
  int sock = net_socket(AF_UNIX, SOCK_STREAM, 0);
  KEXPECT_GE(sock, 0);
  struct sockaddr_un addr;
  addr.sun_family = AF_UNIX;
  kstrcpy(addr.sun_path, kPath);
  KEXPECT_EQ(0, net_bind(sock, (struct sockaddr*)&addr, sizeof(addr)));

  KEXPECT_EQ(0, net_listen(sock, 5));

  KTEST_BEGIN("net_listen(AF_UNIX): already listening socket");
  KEXPECT_EQ(-EINVAL, net_listen(sock, 5));
  KEXPECT_EQ(0, vfs_close(sock));
  KEXPECT_EQ(0, vfs_unlink(kPath));

  KTEST_BEGIN("net_listen(AF_UNIX): unbound socket");
  sock = net_socket(AF_UNIX, SOCK_STREAM, 0);
  KEXPECT_GE(sock, 0);
  KEXPECT_EQ(-EDESTADDRREQ, net_listen(sock, 5));
  KEXPECT_EQ(0, vfs_close(sock));

  KTEST_BEGIN("net_listen(AF_UNIX): negative backlog");
  sock = net_socket(AF_UNIX, SOCK_STREAM, 0);
  KEXPECT_GE(sock, 0);
  KEXPECT_EQ(0, net_bind(sock, (struct sockaddr*)&addr, sizeof(addr)));
  KEXPECT_EQ(0, net_listen(sock, -5));
  KEXPECT_EQ(0, vfs_close(sock));
  KEXPECT_EQ(0, vfs_unlink(kPath));
  // TODO(aoates): verify default value?

  KTEST_BEGIN("net_listen(AF_UNIX): zero backlog");
  sock = net_socket(AF_UNIX, SOCK_STREAM, 0);
  KEXPECT_GE(sock, 0);
  KEXPECT_EQ(0, net_bind(sock, (struct sockaddr*)&addr, sizeof(addr)));
  KEXPECT_EQ(0, net_listen(sock, 0));
  KEXPECT_EQ(0, vfs_close(sock));
  KEXPECT_EQ(0, vfs_unlink(kPath));
  // TODO(aoates): verify default value?

  KTEST_BEGIN("net_listen(AF_UNIX): bad fd");
  KEXPECT_EQ(-EBADF, net_listen(-5, 5));
  KEXPECT_EQ(-EBADF, net_listen(100, 5));

  KTEST_BEGIN("net_listen(AF_UNIX): non-socket fd");
  create_file(kPath, "rwxrwxrwx");
  sock = vfs_open(kPath, VFS_O_RDWR);
  KEXPECT_GE(sock, 0);
  KEXPECT_EQ(-ENOTSOCK, net_listen(sock, 5));
  KEXPECT_EQ(0, vfs_close(sock));
  KEXPECT_EQ(0, vfs_unlink(kPath));

  // TODO(aoates): things to test:
  //  - listen on connected socket
}

void socket_unix_test(void) {
  KTEST_SUITE_BEGIN("Socket (Unix Domain)");
  create_test();
  bind_test();
  listen_test();
}
