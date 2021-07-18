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

#include "common/kassert.h"
#include "memory/kmalloc.h"
#include "net/socket/socket.h"
#include "proc/kthread.h"
#include "proc/fork.h"
#include "proc/scheduler.h"
#include "proc/signal/signal.h"
#include "proc/sleep.h"
#include "proc/umask.h"
#include "proc/user.h"
#include "proc/wait.h"
#include "test/ktest.h"
#include "test/vfs_test_util.h"
#include "user/include/apos/errors.h"
#include "user/include/apos/net/socket/unix.h"
#include "vfs/file.h"
#include "vfs/pipe.h"
#include "vfs/vfs.h"
#include "vfs/vfs_internal.h"
#include "vfs/vfs_test_util.h"

static bool has_sigpipe(void) {
  const ksigset_t sigset = proc_pending_signals(proc_current());
  return ksigismember(&sigset, SIGPIPE);
}

static void create_test(void) {
  KTEST_BEGIN("net_socket_create(AF_UNIX): basic creation");
  socket_t* sock = NULL;
  KEXPECT_EQ(0, net_socket_create(AF_UNIX, SOCK_STREAM, 0, &sock));
  KEXPECT_NE(NULL, sock);
  KEXPECT_EQ(AF_UNIX, sock->s_domain);
  KEXPECT_EQ(SOCK_STREAM, sock->s_type);
  KEXPECT_EQ(0, sock->s_protocol);
  net_socket_destroy(sock);

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
  proc_umask(0);
  KEXPECT_EQ(0,
             vfs_mkdir("_socket_dir", VFS_S_IRWXU | VFS_S_IRWXG | VFS_S_IRWXO));
  KEXPECT_EQ(0, setregid(kGroupB, kGroupA));
  KEXPECT_EQ(0, setreuid(kUserB, kUserA));

  struct sockaddr_un addr;
  addr.sun_family = AF_UNIX;
  kstrcpy(addr.sun_path, "_socket_dir/subdir/sock");

  int sock = net_socket(AF_UNIX, SOCK_STREAM, 0);
  KEXPECT_GE(sock, 0);

  KEXPECT_EQ(0, vfs_mkdir("_socket_dir/subdir", VFS_S_IRUSR | VFS_S_IXUSR));
  KEXPECT_EQ(-EACCES, net_bind(sock, (struct sockaddr*)&addr, sizeof(addr)));
  KEXPECT_EQ(0, vfs_rmdir("_socket_dir/subdir"));

  KTEST_BEGIN("net_bind(AF_UNIX): bind in non-executable directory");
  KEXPECT_EQ(0, vfs_mkdir("_socket_dir/subdir", VFS_S_IRUSR | VFS_S_IWUSR));
  KEXPECT_EQ(-EACCES, net_bind(sock, (struct sockaddr*)&addr, sizeof(addr)));
  KEXPECT_EQ(0, vfs_rmdir("_socket_dir/subdir"));
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
  const kmode_t orig_umask = proc_umask(0);
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

  kpid_t child_pid = proc_fork(&do_bind_mode_test, 0x0);
  KEXPECT_GE(child_pid, 0);
  proc_wait(0x0);
  KEXPECT_EQ(0, vfs_rmdir("_socket_dir"));
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

// Helper to create a socket that's bound to the given path.
int create_bound_socket(const char* path) {
  int sock = net_socket(AF_UNIX, SOCK_STREAM, 0);
  if (sock < 0) {
    return sock;
  }
  if (*path != '\0') {
    struct sockaddr_un server_addr;
    server_addr.sun_family = AF_UNIX;
    kstrcpy(server_addr.sun_path, path);
    int result =
        net_bind(sock, (struct sockaddr*)&server_addr, sizeof(server_addr));
    if (result < 0) {
      return result;
    }
  }
  return sock;
}

// Helper to create a socket that's bound to the given path and listening.
int create_listening_socket(const char* path, int backlog) {
  int server_sock = create_bound_socket(path);
  if (server_sock < 0) {
    return server_sock;
  }
  int result = net_listen(server_sock, backlog);
  if (result < 0) {
    return result;
  }
  return server_sock;
}

// Helper to create two sockets, a client socket and a server socket, bound to
// the given addresses.
int create_socket_pair(const char* client_addr, const char* server_addr,
                       int backlog, int* client_sock_out,
                       int* server_sock_out) {
  *server_sock_out = create_listening_socket(server_addr, backlog);
  if (*server_sock_out < 0) {
    return *server_sock_out;
  }

  *client_sock_out = create_bound_socket(client_addr);
  if (*client_sock_out < 0) {
    return *client_sock_out;
  }
  return 0;
}

static int do_connect(int sock, const char* path) {
  struct sockaddr_un server_addr;
  server_addr.sun_family = AF_UNIX;
  kstrcpy(server_addr.sun_path, path);
  return net_connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr));
}

static int do_accept(int sock, struct sockaddr_un* addr) {
  socklen_t addr_len = sizeof(struct sockaddr_un);
  return net_accept(sock, (struct sockaddr*)addr, &addr_len);
}

static int connect_and_close(const char* addr) {
  int sock = net_socket(AF_UNIX, SOCK_STREAM, 0);
  if (sock < 0) return sock;
  int result = do_connect(sock, addr);
  vfs_close(sock);
  return result;
}

static int accept_and_close(int server_sock) {
  int client_sock = do_accept(server_sock, NULL);
  if (client_sock < 0) return client_sock;

  vfs_close(client_sock);
  return 0;
}

static void connect_test(void) {
  const char kClientPath[] = "_socket_client_path";
  const char kServerPath[] = "_socket_server_path";

  struct sockaddr_un server_addr;
  server_addr.sun_family = AF_UNIX;
  kstrcpy(server_addr.sun_path, kServerPath);

  KTEST_BEGIN("net_connect(AF_UNIX): basic connect");
  int server_sock = net_socket(AF_UNIX, SOCK_STREAM, 0);
  KEXPECT_GE(server_sock, 0);
  KEXPECT_EQ(0, net_bind(server_sock, (struct sockaddr*)&server_addr,
                         sizeof(server_addr)));
  KEXPECT_EQ(0, net_listen(server_sock, 5));

  int client_sock = net_socket(AF_UNIX, SOCK_STREAM, 0);
  KEXPECT_GE(client_sock, 0);
  KEXPECT_EQ(0, net_connect(client_sock, (struct sockaddr*)&server_addr,
                            sizeof(server_addr)));

  struct sockaddr_un accept_addr;
  socklen_t addr_len = 2 * sizeof(struct sockaddr_un);  // A lie!
  int accepted_sock =
      net_accept(server_sock, (struct sockaddr*)&accept_addr, &addr_len);
  KEXPECT_GE(accepted_sock, 0);
  KEXPECT_EQ(AF_UNIX, accept_addr.sun_family);
  KEXPECT_STREQ("", accept_addr.sun_path);
  KEXPECT_EQ(sizeof(struct sockaddr_un), addr_len);

  KEXPECT_EQ(0, vfs_close(accepted_sock));
  KEXPECT_EQ(0, vfs_close(client_sock));
  KEXPECT_EQ(0, vfs_close(server_sock));
  KEXPECT_EQ(0, vfs_unlink(kServerPath));

  KTEST_BEGIN("net_connect(AF_UNIX): connect from bound socket");
  KEXPECT_EQ(0, create_socket_pair(kClientPath, kServerPath, 5, &client_sock,
                                   &server_sock));
  KEXPECT_EQ(0, do_connect(client_sock, kServerPath));
  accepted_sock = do_accept(server_sock, &accept_addr);
  KEXPECT_GE(accepted_sock, 0);

  KEXPECT_EQ(AF_UNIX, accept_addr.sun_family);
  KEXPECT_STREQ(kClientPath, accept_addr.sun_path);

  vfs_close(accepted_sock);
  vfs_close(client_sock);
  KEXPECT_EQ(0, vfs_unlink(kClientPath));

  KTEST_BEGIN(
      "net_connect(AF_UNIX): connect from bound socket (renamed before "
      "connection)");
  client_sock = create_bound_socket(kClientPath);
  KEXPECT_GE(client_sock, 0);
  KEXPECT_EQ(0, vfs_rename(kClientPath, "_client_socket2"));
  KEXPECT_EQ(0, do_connect(client_sock, kServerPath));
  accepted_sock = do_accept(server_sock, &accept_addr);
  KEXPECT_GE(accepted_sock, 0);

  KEXPECT_EQ(AF_UNIX, accept_addr.sun_family);
  // We should get the pre-rename path.
  KEXPECT_STREQ(kClientPath, accept_addr.sun_path);

  vfs_close(accepted_sock);
  vfs_close(client_sock);
  KEXPECT_EQ(0, vfs_unlink("_client_socket2"));

  KTEST_BEGIN(
      "net_connect(AF_UNIX): connect from bound socket (deleted before "
      "connection)");
  client_sock = create_bound_socket(kClientPath);
  KEXPECT_GE(client_sock, 0);
  KEXPECT_EQ(0, vfs_unlink(kClientPath));
  KEXPECT_EQ(0, do_connect(client_sock, kServerPath));
  accepted_sock = do_accept(server_sock, &accept_addr);
  KEXPECT_GE(accepted_sock, 0);

  KEXPECT_EQ(AF_UNIX, accept_addr.sun_family);
  // We should get the pre-delete path.
  KEXPECT_STREQ(kClientPath, accept_addr.sun_path);

  vfs_close(accepted_sock);
  vfs_close(client_sock);

  KTEST_BEGIN(
      "net_connect(AF_UNIX): connect from bound socket (linked before "
      "connection)");
  client_sock = create_bound_socket(kClientPath);
  KEXPECT_GE(client_sock, 0);
  KEXPECT_EQ(0, vfs_link(kClientPath, "_client_socket2"));
  KEXPECT_EQ(0, do_connect(client_sock, kServerPath));
  accepted_sock = do_accept(server_sock, &accept_addr);
  KEXPECT_GE(accepted_sock, 0);

  KEXPECT_EQ(AF_UNIX, accept_addr.sun_family);
  // We should get the pre-link path.
  KEXPECT_STREQ(kClientPath, accept_addr.sun_path);

  vfs_close(accepted_sock);
  vfs_close(client_sock);
  KEXPECT_EQ(0, vfs_unlink(kClientPath));
  KEXPECT_EQ(0, vfs_unlink("_client_socket2"));

  KTEST_BEGIN("net_connect(AF_UNIX): connect through symlink");
  client_sock = net_socket(AF_UNIX, SOCK_STREAM, 0);
  KEXPECT_GE(client_sock, 0);
  KEXPECT_EQ(0, vfs_symlink(kServerPath, "_server_sock_link"));
  KEXPECT_EQ(0, do_connect(client_sock, "_server_sock_link"));
  accepted_sock = do_accept(server_sock, &accept_addr);
  KEXPECT_GE(accepted_sock, 0);
  vfs_close(accepted_sock);
  vfs_close(client_sock);
  KEXPECT_EQ(0, vfs_unlink("_server_sock_link"));

  KTEST_BEGIN("net_connect(AF_UNIX): connect through hard link");
  client_sock = net_socket(AF_UNIX, SOCK_STREAM, 0);
  KEXPECT_GE(client_sock, 0);
  KEXPECT_EQ(0, vfs_link(kServerPath, "_server_sock_link"));
  KEXPECT_EQ(0, do_connect(client_sock, "_server_sock_link"));
  accepted_sock = do_accept(server_sock, &accept_addr);
  KEXPECT_GE(accepted_sock, 0);
  vfs_close(accepted_sock);
  vfs_close(client_sock);
  KEXPECT_EQ(0, vfs_unlink("_server_sock_link"));

  // Tests for connecting to bad or invalid addresses.

  KTEST_BEGIN("net_connect(AF_UNIX): connect to non-socket");
  create_file("_file_server_dst", "rwxrwxrwx");
  vfs_mkdir("_dir_server_dst", VFS_S_IRWXU);
  client_sock = net_socket(AF_UNIX, SOCK_STREAM, 0);
  KEXPECT_GE(client_sock, 0);
  KEXPECT_EQ(-ENOTSOCK, do_connect(client_sock, "_file_server_dst"));
  KEXPECT_EQ(-ENOTSOCK, do_connect(client_sock, "_dir_server_dst"));
  KEXPECT_EQ(0, vfs_unlink("_file_server_dst"));
  KEXPECT_EQ(0, vfs_rmdir("_dir_server_dst"));

  KTEST_BEGIN("net_connect(AF_UNIX): connect to non-existent address");
  KEXPECT_EQ(-ENOENT, do_connect(client_sock, "_doesnt_exist"));

  KTEST_BEGIN("net_connect(AF_UNIX): connect to unbound socket address");
  int server_sock2 = create_bound_socket("_bound_socket_path");
  KEXPECT_GE(server_sock2, 0);
  KEXPECT_EQ(0, vfs_close(server_sock2));
  KEXPECT_EQ(-ECONNREFUSED, do_connect(client_sock, "_bound_socket_path"));
  KEXPECT_EQ(0, vfs_unlink("_bound_socket_path"));

  KTEST_BEGIN(
      "net_connect(AF_UNIX): connect to previously-listening unbound socket "
      "address");
  server_sock2 = create_listening_socket("_bound_socket_path", 5);
  KEXPECT_GE(server_sock2, 0);
  KEXPECT_EQ(0, vfs_close(server_sock2));
  KEXPECT_EQ(-ECONNREFUSED, do_connect(client_sock, "_bound_socket_path"));
  KEXPECT_EQ(0, vfs_unlink("_bound_socket_path"));

  KTEST_BEGIN("net_connect(AF_UNIX): connect to non-listening socket");
  server_sock2 = create_bound_socket("_bound_socket_path");
  KEXPECT_GE(server_sock2, 0);
  KEXPECT_EQ(-ECONNREFUSED, do_connect(client_sock, "_bound_socket_path"));
  KEXPECT_EQ(0, vfs_close(server_sock2));
  KEXPECT_EQ(0, vfs_unlink("_bound_socket_path"));

  KTEST_BEGIN("net_connect(AF_UNIX): connect to connected socket");
  int client_sock2 = create_bound_socket("_bound_socket_path");
  KEXPECT_GE(client_sock2, 0);
  KEXPECT_EQ(0, do_connect(client_sock2, kServerPath));;
  KEXPECT_EQ(-ECONNREFUSED, do_connect(client_sock, "_bound_socket_path"));
  KEXPECT_EQ(0, vfs_close(net_accept(server_sock, NULL, NULL)));
  KEXPECT_EQ(0, vfs_close(client_sock2));
  KEXPECT_EQ(0, vfs_unlink("_bound_socket_path"));

  KTEST_BEGIN(
      "net_connect(AF_UNIX): connect to removed file where server socket is "
      "still listening");
  server_sock2 = create_listening_socket("_bound_socket_path", 5);
  KEXPECT_GE(server_sock2, 0);
  KEXPECT_EQ(0, vfs_unlink("_bound_socket_path"));
  KEXPECT_EQ(-ENOENT, do_connect(client_sock, "_bound_socket_path"));
  KEXPECT_EQ(0, vfs_close(server_sock2));

  KTEST_BEGIN("net_connect(AF_UNIX): connect to self address");
  client_sock2 = create_bound_socket("_bound_socket_path");
  KEXPECT_GE(client_sock2, 0);
  KEXPECT_EQ(-ECONNREFUSED, do_connect(client_sock2, "_bound_socket_path"));
  KEXPECT_EQ(0, vfs_close(client_sock2));
  KEXPECT_EQ(0, vfs_unlink("_bound_socket_path"));

  KEXPECT_EQ(0, vfs_close(client_sock));

  KTEST_BEGIN("net_connect(AF_UNIX): connect on already-connected socket");
  KEXPECT_EQ(0, net_accept_queue_length(server_sock));
  client_sock = net_socket(AF_UNIX, SOCK_STREAM, 0);
  KEXPECT_GE(client_sock, 0);
  KEXPECT_EQ(0, do_connect(client_sock, kServerPath));
  KEXPECT_EQ(-EISCONN, do_connect(client_sock, kServerPath));
  KEXPECT_EQ(0, vfs_close(net_accept(server_sock, NULL, NULL)));
  KEXPECT_EQ(0, vfs_close(client_sock));

  KTEST_BEGIN("net_connect(AF_UNIX): connect on already-accepted socket");
  KEXPECT_EQ(0, net_accept_queue_length(server_sock));
  client_sock = net_socket(AF_UNIX, SOCK_STREAM, 0);
  KEXPECT_GE(client_sock, 0);
  KEXPECT_EQ(0, do_connect(client_sock, kServerPath));
  client_sock2 = net_accept(server_sock, NULL, NULL);
  KEXPECT_EQ(-EISCONN, do_connect(client_sock, kServerPath));
  KEXPECT_EQ(0, vfs_close(client_sock));
  KEXPECT_EQ(0, vfs_close(client_sock2));

  // TODO(aoates): test multiple simultaneous calls to connect() (should be
  // atomic).

  KTEST_BEGIN("net_connect(AF_UNIX): connect on listening socket");
  KEXPECT_EQ(-EOPNOTSUPP, do_connect(server_sock, kServerPath));
  KEXPECT_EQ(-EOPNOTSUPP, do_connect(server_sock, "_another_path"));

  KTEST_BEGIN("net_accept(AF_UNIX): accept when peer has already closed");
  KEXPECT_EQ(0, net_accept_queue_length(server_sock));
  client_sock = net_socket(AF_UNIX, SOCK_STREAM, 0);
  KEXPECT_GE(client_sock, 0);
  KEXPECT_EQ(0, do_connect(client_sock, kServerPath));
  KEXPECT_EQ(0, vfs_close(client_sock));

  kmemset(&accept_addr, 0xFF, sizeof(accept_addr));
  client_sock2 = do_accept(server_sock, &accept_addr);
  KEXPECT_EQ(AF_UNIX, accept_addr.sun_family);
  KEXPECT_STREQ("", accept_addr.sun_path);
  KEXPECT_EQ(-EISCONN, do_connect(client_sock2, kServerPath));
  // TODO(aoates): test read/write and other operations on this socket.
  KEXPECT_EQ(0, vfs_close(client_sock2));

  KTEST_BEGIN("net_accept(AF_UNIX): close server with unaccepted connections");
  KEXPECT_EQ(0, create_socket_pair(kClientPath, "_server_sock2", 5,
                                   &client_sock, &server_sock2));
  KEXPECT_EQ(0, do_connect(client_sock, "_server_sock2"));
  KEXPECT_EQ(1, net_accept_queue_length(server_sock2));
  KEXPECT_EQ(0, vfs_close(server_sock2));
  // TODO(aoates): test read/write and other operations on this socket.
  KEXPECT_EQ(0, vfs_close(client_sock));
  KEXPECT_EQ(0, vfs_unlink(kClientPath));
  KEXPECT_EQ(0, vfs_unlink("_server_sock2"));

  KTEST_BEGIN("net_accept(AF_UNIX): NULL/NULL addr/len parameters");
  KEXPECT_EQ(0, connect_and_close(kServerPath));
  accepted_sock = net_accept(server_sock, NULL, NULL);
  KEXPECT_GE(accepted_sock, 0);
  KEXPECT_EQ(0, vfs_close(accepted_sock));

  KTEST_BEGIN("net_accept(AF_UNIX): NULL/not-NULL addr/len parameters");
  KEXPECT_EQ(0, connect_and_close(kServerPath));
  addr_len = 3;
  accepted_sock = net_accept(server_sock, NULL, &addr_len);
  KEXPECT_GE(accepted_sock, 0);
  KEXPECT_EQ(3, addr_len);
  KEXPECT_EQ(0, vfs_close(accepted_sock));

  KTEST_BEGIN("net_accept(AF_UNIX): not-NULL/NULL addr/len parameters");
  KEXPECT_EQ(0, connect_and_close(kServerPath));
  kmemset(&accept_addr, 0xFF, sizeof(accept_addr));
  accepted_sock = net_accept(server_sock, (struct sockaddr*)&accept_addr, NULL);
  KEXPECT_GE(accepted_sock, 0);
  KEXPECT_EQ(0, vfs_close(accepted_sock));

  KTEST_BEGIN("net_accept(AF_UNIX): too-small address struct");
  client_sock = create_bound_socket(kClientPath);
  KEXPECT_EQ(0, do_connect(client_sock, kServerPath));
  kmemset(&accept_addr, 0xFF, sizeof(accept_addr));
  addr_len = 10;
  accepted_sock =
      net_accept(server_sock, (struct sockaddr*)&accept_addr, &addr_len);
  KEXPECT_GE(accepted_sock, 0);
  KEXPECT_EQ(sizeof(struct sockaddr_un), addr_len);
  KEXPECT_EQ(AF_UNIX, accept_addr.sun_family);
  char truncated_str[50];
  kmemset(truncated_str, 0, 50);
  kstrncpy(truncated_str, kClientPath,
           10 - offsetof(struct sockaddr_un, sun_path) - 1);
  KEXPECT_STREQ(truncated_str, accept_addr.sun_path);
  KEXPECT_EQ(0, vfs_close(accepted_sock));
  KEXPECT_EQ(0, vfs_close(client_sock));
  KEXPECT_EQ(0, vfs_unlink(kClientPath));

  KTEST_BEGIN(
      "net_accept(AF_UNIX): too-small address struct (just enough for family)");
  client_sock = create_bound_socket(kClientPath);
  KEXPECT_EQ(0, do_connect(client_sock, kServerPath));
  kmemset(&accept_addr, 'a', sizeof(accept_addr));
  addr_len = offsetof(struct sockaddr_un, sun_path) + 1;
  accepted_sock =
      net_accept(server_sock, (struct sockaddr*)&accept_addr, &addr_len);
  KEXPECT_GE(accepted_sock, 0);
  KEXPECT_EQ(sizeof(struct sockaddr_un), addr_len);
  KEXPECT_EQ('a', ((const char*)&accept_addr)[0]);
  KEXPECT_EQ(0, vfs_close(accepted_sock));
  KEXPECT_EQ(0, vfs_close(client_sock));
  KEXPECT_EQ(0, vfs_unlink(kClientPath));

  KTEST_BEGIN("net_accept(AF_UNIX): too-small address struct (less than path)");
  client_sock = create_bound_socket(kClientPath);
  KEXPECT_EQ(0, do_connect(client_sock, kServerPath));
  kmemset(&accept_addr, 'a', sizeof(accept_addr));
  addr_len = offsetof(struct sockaddr_un, sun_path) - 1;
  accepted_sock =
      net_accept(server_sock, (struct sockaddr*)&accept_addr, &addr_len);
  KEXPECT_GE(accepted_sock, 0);
  KEXPECT_EQ(sizeof(struct sockaddr_un), addr_len);
  KEXPECT_EQ('a', ((const char*)&accept_addr)[0]);
  KEXPECT_EQ(0, vfs_close(accepted_sock));
  KEXPECT_EQ(0, vfs_close(client_sock));
  KEXPECT_EQ(0, vfs_unlink(kClientPath));

  // Tests for invalid parameters to connect() and accept().

  KTEST_BEGIN("net_connect(AF_UNIX): connect with wrong addr family");
  client_sock = net_socket(AF_UNIX, SOCK_STREAM, 0);
  KEXPECT_GE(client_sock, 0);
  server_addr.sun_family = AF_UNSPEC;
  KEXPECT_EQ(-EAFNOSUPPORT,
             net_connect(client_sock, (struct sockaddr*)&server_addr,
                         sizeof(server_addr)));
  vfs_close(client_sock);

  KTEST_BEGIN("net_connect(AF_UNIX): connect with bad FD");
  KEXPECT_EQ(-EBADF, net_connect(-1, (struct sockaddr*)&server_addr,
                                 sizeof(server_addr)));
  KEXPECT_EQ(-EBADF, net_connect(100, (struct sockaddr*)&server_addr,
                                 sizeof(server_addr)));

  KTEST_BEGIN("net_connect(AF_UNIX): connect with non-socket FD");
  int pipe_fds[2];
  KEXPECT_EQ(0, vfs_pipe(pipe_fds));
  KEXPECT_EQ(-ENOTSOCK, net_connect(pipe_fds[0], (struct sockaddr*)&server_addr,
                                    sizeof(server_addr)));

  KTEST_BEGIN("net_accept(AF_UNIX): accept with bad FD");
  KEXPECT_EQ(-EBADF, do_accept(-1, &accept_addr));
  KEXPECT_EQ(-EBADF, do_accept(100, &accept_addr));

  KTEST_BEGIN("net_accept(AF_UNIX): accept with non-socket FD");
  KEXPECT_EQ(-ENOTSOCK, do_accept(pipe_fds[0], &accept_addr));
  KEXPECT_EQ(0, vfs_close(pipe_fds[0]));
  KEXPECT_EQ(0, vfs_close(pipe_fds[1]));

  KTEST_BEGIN("net_accept(AF_UNIX): accept on unbound socket");
  client_sock = net_socket(AF_UNIX, SOCK_STREAM, 0);
  KEXPECT_GE(client_sock, 0);
  KEXPECT_EQ(-EINVAL, do_accept(client_sock, &accept_addr));
  KEXPECT_EQ(0, vfs_close(client_sock));

  KTEST_BEGIN("net_accept(AF_UNIX): accept on non-listening socket");
  client_sock = create_bound_socket(kClientPath);
  KEXPECT_GE(client_sock, 0);
  KEXPECT_EQ(-EINVAL, do_accept(client_sock, &accept_addr));
  KEXPECT_EQ(0, vfs_unlink(kClientPath));
  KEXPECT_EQ(0, vfs_close(client_sock));

  KTEST_BEGIN("net_accept(AF_UNIX): accept on connected socket (client)");
  client_sock = create_bound_socket(kClientPath);
  KEXPECT_GE(client_sock, 0);
  KEXPECT_EQ(0, do_connect(client_sock, kServerPath));
  KEXPECT_EQ(-EINVAL, do_accept(client_sock, &accept_addr));

  KTEST_BEGIN("net_accept(AF_UNIX): accept on connected socket (server)");
  accepted_sock = do_accept(server_sock, NULL);
  KEXPECT_GE(accepted_sock, 0);
  KEXPECT_EQ(-EINVAL, do_accept(accepted_sock, &accept_addr));
  KEXPECT_EQ(0, vfs_close(client_sock));
  KEXPECT_EQ(0, vfs_close(accepted_sock));
  KEXPECT_EQ(0, vfs_unlink(kClientPath));

  KEXPECT_EQ(0, vfs_close(server_sock));
  KEXPECT_EQ(0, vfs_unlink(kServerPath));

  // TODO(aoates): things to test:
  //  - connect from client bound through symlink (should give symlink address,
  //  not symlink target address)
  //  - as above, but remove target and try to rebind (this fails on OS X? I
  //  think should succeed)
  //  - bind on connected socket
  //  - connect interrupted by signal
  //  - forked sockets
  //  - read/write on connected but not accepted sockets
  //  - as above, but server socket was closed/deleted
  //  - read/write on sockets accepted after client was closed
  //  - all ops on accepted sockets (connect, listen, bind, etc)
}

static int find_backlog_length(const char* path) {
  for (int i = 0; i < 1000; i++) {
    int result = connect_and_close(path);
    if (result == -ECONNREFUSED) {
      return i;
    } else if (result < 0) {
      return result;
    }
  }
  return -EINVAL;
}

static void connect_backlog_test(void) {
  const char kPath[] = "_server_sock";
  KTEST_BEGIN("net_accept(AF_UNIX): enforces backlog");
  int server_sock = create_listening_socket(kPath, 3);
  KEXPECT_GE(server_sock, 0);
  for (int i = 0; i < 3; ++i) {
    KEXPECT_EQ(0, connect_and_close(kPath));
  }
  KEXPECT_EQ(-ECONNREFUSED, connect_and_close(kPath));
  KEXPECT_EQ(0, accept_and_close(server_sock));
  KEXPECT_EQ(0, connect_and_close(kPath));
  KEXPECT_EQ(-ECONNREFUSED, connect_and_close(kPath));
  KEXPECT_EQ(0, accept_and_close(server_sock));
  KEXPECT_EQ(0, accept_and_close(server_sock));
  KEXPECT_EQ(0, connect_and_close(kPath));
  KEXPECT_EQ(0, connect_and_close(kPath));
  KEXPECT_EQ(-ECONNREFUSED, connect_and_close(kPath));
  KEXPECT_EQ(0, vfs_close(server_sock));
  KEXPECT_EQ(0, vfs_unlink(kPath));

  KTEST_BEGIN("net_accept(AF_UNIX): enforces backlog #2");
  server_sock = create_listening_socket(kPath, 8);
  KEXPECT_EQ(8, find_backlog_length(kPath));
  KEXPECT_EQ(0, vfs_close(server_sock));
  KEXPECT_EQ(0, vfs_unlink(kPath));

  KTEST_BEGIN("net_accept(AF_UNIX): enforces backlog higher than default");
  server_sock = create_listening_socket(kPath, 20);
  KEXPECT_EQ(20, find_backlog_length(kPath));
  KEXPECT_EQ(0, vfs_close(server_sock));
  KEXPECT_EQ(0, vfs_unlink(kPath));

  KTEST_BEGIN("net_accept(AF_UNIX): caps backlog to 128");
  server_sock = create_listening_socket(kPath, 500);
  KEXPECT_EQ(128, find_backlog_length(kPath));
  KEXPECT_EQ(0, vfs_close(server_sock));
  KEXPECT_EQ(0, vfs_unlink(kPath));

  KTEST_BEGIN("net_accept(AF_UNIX): backlog of 0 gets default");
  server_sock = create_listening_socket(kPath, 0);
  KEXPECT_EQ(10, find_backlog_length(kPath));
  KEXPECT_EQ(0, vfs_close(server_sock));
  KEXPECT_EQ(0, vfs_unlink(kPath));

  KTEST_BEGIN("net_accept(AF_UNIX): negative backlog gets default");
  server_sock = create_listening_socket(kPath, -5);
  KEXPECT_EQ(10, find_backlog_length(kPath));
  KEXPECT_EQ(0, vfs_close(server_sock));
  KEXPECT_EQ(0, vfs_unlink(kPath));
}

typedef struct {
  int fd;
  kthread_queue_t started_queue;
  bool done;
  int result;
} accept_thread_args_t;

static void* do_accept_thread(void* arg) {
  accept_thread_args_t* args = (accept_thread_args_t*)arg;
  KEXPECT_EQ(false, args->done);

  scheduler_wake_all(&args->started_queue);
  args->result = do_accept(args->fd, NULL);
  args->done = true;
  return 0x0;
}

static void do_accept_thread_proc(void* arg) {
  do_accept_thread(arg);
}

static void accept_blocking_test(void) {
  const char kServerPath[] = "_server_sock";
  KTEST_BEGIN("net_accept(AF_UNIX): blocks until a connection is ready");
  int server_sock = create_listening_socket(kServerPath, 5);
  KEXPECT_GE(server_sock, 0);
  int client_sock = net_socket(AF_UNIX, SOCK_STREAM, 0);
  KEXPECT_GE(client_sock, 0);

  kthread_t thread;
  accept_thread_args_t args;
  args.fd = server_sock;
  kthread_queue_init(&args.started_queue);
  args.done = false;
  KEXPECT_EQ(0, proc_thread_create(&thread, &do_accept_thread, &args));
  scheduler_wait_on(&args.started_queue);
  // Give accept() some more time to run.
  ksleep(50);
  KEXPECT_EQ(false, args.done);

  KEXPECT_EQ(0, do_connect(client_sock, kServerPath));
  kthread_join(thread);
  KEXPECT_EQ(true, args.done);
  KEXPECT_GE(args.result, 0);
  // TODO(aoates): test read/write between the sockets.
  KEXPECT_EQ(0, vfs_close(client_sock));
  KEXPECT_EQ(0, vfs_close(args.result));

  KTEST_BEGIN("net_accept(AF_UNIX): signal during blocking accept()");
  args.done = false;
  // For this one, we use fork for consistent signal delivery.
  kpid_t child_pid = proc_fork(&do_accept_thread_proc, &args);
  KEXPECT_GE(child_pid, 0);
  scheduler_wait_on(&args.started_queue);
  proc_force_signal(proc_get(child_pid), SIGUSR1);
  KEXPECT_EQ(child_pid, proc_wait(0x0));
  KEXPECT_EQ(true, args.done);
  KEXPECT_GE(args.result, -EINTR);

  KTEST_BEGIN("net_accept(AF_UNIX): accept() in many threads");
  const int kThreads = 5;
  kpid_t child_pids[kThreads];
  accept_thread_args_t multi_args[kThreads];
  for (int i = 0; i < kThreads; ++i) {
    multi_args[i].fd = server_sock;
    kthread_queue_init(&multi_args[i].started_queue);
    multi_args[i].done = false;
    child_pids[i] = proc_fork(&do_accept_thread_proc, &multi_args[i]);
    KEXPECT_GE(child_pids[i], 0);
    scheduler_wait_on(&multi_args[i].started_queue);
  }

  // Connect, and make sure that only one thread wins.
  client_sock = net_socket(AF_UNIX, SOCK_STREAM, 0);
  KEXPECT_EQ(0, do_connect(client_sock, kServerPath));
  for (int i = 0; i < 100; ++i) scheduler_yield();  // Let everyone run.
  for (int i = 0; i < kThreads; ++i) {
    proc_force_signal(proc_get(child_pids[i]), SIGUSR1);
    KEXPECT_GE(proc_waitpid(child_pids[i], NULL, 0), 0);
  }
  int total_done = 0;
  for (int i = 0; i < kThreads; ++i) {
    if (multi_args[i].result >= 0) {
      total_done++;
    } else {
      KEXPECT_EQ(-EINTR, multi_args[i].result);
    }
  }
  KEXPECT_EQ(1, total_done);
  KEXPECT_EQ(0, vfs_close(client_sock));

  KTEST_BEGIN("net_accept(AF_UNIX): close() FD while blocked in accept()");
  client_sock = net_socket(AF_UNIX, SOCK_STREAM, 0);
  KEXPECT_GE(client_sock, 0);
  args.done = false;
  KEXPECT_EQ(0, proc_thread_create(&thread, &do_accept_thread, &args));
  scheduler_wait_on(&args.started_queue);
  // Make sure we get good and stuck in accept()
  for (int i = 0; i < 20; ++i) scheduler_yield();
  KEXPECT_EQ(false, args.done);
  KEXPECT_EQ(0, vfs_close(server_sock));
  server_sock = -1;
  for (int i = 0; i < 20; ++i) scheduler_yield();

  // accept() should still be pending, even though the fd was closed.
  KEXPECT_EQ(false, kthread_is_done(thread));

  // connect() should still work, even though the accepting fd was closed.
  KEXPECT_EQ(0, do_connect(client_sock, kServerPath));
  kthread_join(thread);
  KEXPECT_EQ(true, args.done);
  KEXPECT_GE(args.result, 0);
  // TODO(aoates): test reading/writing between them.
  KEXPECT_EQ(0, vfs_close(client_sock));
  KEXPECT_EQ(0, vfs_close(args.result));
  KEXPECT_EQ(0, vfs_unlink(kServerPath));

  // TODO(aoates): test shutdown call during blocking accept()
  // TODO(aoates): test accept() on dup'd socket (and after shutting down the
  // twin fd.
}

typedef struct {
  int sock;
  void* buf;
  size_t len;
  bool started;
  int result;
} async_args_t;

static void recv_proc(void* x) {
  async_args_t* args = (async_args_t*)x;
  args->started = true;
  args->result = net_recv(args->sock, args->buf, args->len, 0);
}

static void* recv_thread(void* x) {
  recv_proc(x);
  return NULL;
}

static void send_proc(void* x) {
  async_args_t* args = (async_args_t*)x;
  args->started = true;
  args->result = net_send(args->sock, args->buf, args->len, 0);
}

static void* send_thread(void* x) {
  send_proc(x);
  return NULL;
}

static kthread_t start_async(void* (*func)(void*), async_args_t* args) {
  kthread_t thread;
  args->result = -100;
  args->started = false;
  KEXPECT_EQ(0, proc_thread_create(&thread, func, args));
  while (!args->started) scheduler_yield();
  return thread;
}

static kpid_t start_async_proc(void (*func)(void*), async_args_t* args) {
  args->result = -100;
  args->started = false;
  kpid_t child_pid = proc_fork(func, args);
  KEXPECT_GE(child_pid, 0);
  while (!args->started) scheduler_yield();
  return child_pid;
}

void make_connected_pair(int listen, int* s1, int* s2) {
  *s1 = net_socket(AF_UNIX, SOCK_STREAM, 0);
  KEXPECT_GE(*s1, 0);
  KEXPECT_EQ(0, do_connect(*s1, "_server_sock"));
  *s2 = do_accept(listen, NULL);
  KEXPECT_GE(*s2, 0);
}

static void send_recv_test(void) {
  const char kServerPath[] = "_server_sock";
  KTEST_BEGIN("sockets (AF_UNIX): basic send/recv");
  int listen_sock = create_listening_socket(kServerPath, 5);
  KEXPECT_GE(listen_sock, 0);
  int s1, s2;
  make_connected_pair(listen_sock, &s1, &s2);

  KEXPECT_EQ(2, net_send(s1, "ab", 2, 0));
  KEXPECT_EQ(3, net_send(s1, "cde", 3, 0));

  char buf[100];
  KEXPECT_EQ(3, net_recv(s2, buf, 3, 0));
  KEXPECT_EQ(2, net_recv(s2, buf + 3, 100, 0));
  buf[5] = '\0';
  KEXPECT_STREQ("abcde", buf);

  // Try the other direction
  KEXPECT_EQ(2, net_send(s2, "ab", 2, 0));
  KEXPECT_EQ(3, net_send(s2, "cde", 3, 0));

  kmemset(buf, 0, 100);
  KEXPECT_EQ(3, net_recv(s1, buf, 3, 0));
  KEXPECT_EQ(2, net_recv(s1, buf + 3, 100, 0));
  KEXPECT_STREQ("abcde", buf);

  KTEST_BEGIN("sockets (AF_UNIX): recv() blocks until data");
  async_args_t async_args;
  async_args.sock = s1;
  async_args.buf = buf;
  async_args.len = 100;
  kmemset(buf, 0, 100);
  kthread_t thread = start_async(&recv_thread, &async_args);
  KEXPECT_EQ(false, kthread_is_done(thread));
  KEXPECT_EQ(3, net_send(s2, "abc", 3, 0));
  kthread_join(thread);
  KEXPECT_EQ(3, async_args.result);
  KEXPECT_STREQ("abc", buf);

  KTEST_BEGIN("sockets (AF_UNIX): send() blocks until buffer room");
  const int kBigBufSize = 32 * 1024;
  void* bigbuf = kmalloc(kBigBufSize);
  int max_send_buf = net_send(s1, bigbuf, kBigBufSize, 0);
  KEXPECT_GE(max_send_buf, 1024);

  async_args.sock = s1;
  async_args.buf = bigbuf;
  async_args.len = kBigBufSize;
  thread = start_async(&send_thread, &async_args);
  KEXPECT_EQ(false, kthread_is_done(thread));
  KEXPECT_EQ(3, net_recv(s2, buf, 3, 0));
  kthread_join(thread);
  KEXPECT_EQ(3, async_args.result);
  // Drain the rest of the buffer.
  KEXPECT_EQ(max_send_buf, net_recv(s2, bigbuf, kBigBufSize, 0));

  KTEST_BEGIN("sockets (AF_UNIX): close() during blocking recv()");
  async_args.sock = s1;
  async_args.buf = buf;
  async_args.len = 100;
  kmemset(buf, 0, 100);
  thread = start_async(&recv_thread, &async_args);
  KEXPECT_EQ(false, kthread_is_done(thread));
  KEXPECT_EQ(0, vfs_close(s2));
  kthread_join(thread);
  KEXPECT_EQ(0, async_args.result);
  vfs_close(s1);

  KTEST_BEGIN("sockets (AF_UNIX): close() during blocking send()");
  KEXPECT_EQ(false, has_sigpipe());
  make_connected_pair(listen_sock, &s1, &s2);
  max_send_buf = net_send(s1, bigbuf, kBigBufSize, 0);
  KEXPECT_GE(max_send_buf, 1024);
  async_args.sock = s1;
  async_args.buf = bigbuf;
  async_args.len = kBigBufSize;
  thread = start_async(&send_thread, &async_args);
  KEXPECT_EQ(false, kthread_is_done(thread));
  KEXPECT_EQ(0, vfs_close(s2));
  kthread_join(thread);
  KEXPECT_EQ(true, has_sigpipe());
  KEXPECT_EQ(-EPIPE, async_args.result);
  proc_suppress_signal(proc_current(), SIGPIPE);
  vfs_close(s1);

  KTEST_BEGIN("sockets (AF_UNIX): recv() on closed connection");
  make_connected_pair(listen_sock, &s1, &s2);
  KEXPECT_EQ(3, net_send(s2, "abc", 3, 0));
  KEXPECT_EQ(0, vfs_close(s2));
  kmemset(buf, 0, 100);
  KEXPECT_EQ(3, net_recv(s1, buf, 100, 0));
  KEXPECT_STREQ("abc", buf);
  KEXPECT_EQ(0, net_recv(s1, buf, 100, 0));
  KEXPECT_EQ(0, net_recv(s1, buf, 100, 0));
  vfs_close(s1);

  // Now try when there's no data on the socket at the start of the call.
  make_connected_pair(listen_sock, &s1, &s2);
  KEXPECT_EQ(0, vfs_close(s2));
  KEXPECT_EQ(0, net_recv(s1, buf, 100, 0));
  KEXPECT_EQ(0, net_recv(s1, buf, 100, 0));
  vfs_close(s1);

  KTEST_BEGIN("sockets (AF_UNIX): send() on closed connection");
  make_connected_pair(listen_sock, &s1, &s2);
  KEXPECT_EQ(false, has_sigpipe());
  KEXPECT_EQ(0, vfs_close(s2));
  KEXPECT_EQ(-EPIPE, net_send(s1, buf, 100, 0));
  KEXPECT_EQ(true, has_sigpipe());
  KEXPECT_EQ(-EPIPE, net_send(s1, buf, 100, 0));
  proc_suppress_signal(proc_current(), SIGPIPE);
  vfs_close(s1);

  KTEST_BEGIN("sockets (AF_UNIX): signal during blocking recv()");
  make_connected_pair(listen_sock, &s1, &s2);
  async_args.sock = s1;
  async_args.buf = buf;
  async_args.len = 100;
  kmemset(buf, 0, 100);
  // For this one, we use fork for consistent signal delivery.
  kpid_t child_pid = start_async_proc(&recv_proc, &async_args);
  proc_force_signal(proc_get(child_pid), SIGUSR1);
  KEXPECT_EQ(child_pid, proc_wait(0x0));
  KEXPECT_GE(async_args.result, -EINTR);

  KTEST_BEGIN("sockets (AF_UNIX): signal during blocking send()");
  max_send_buf = net_send(s1, bigbuf, kBigBufSize, 0);
  KEXPECT_GE(max_send_buf, 1024);
  child_pid = start_async_proc(&send_proc, &async_args);
  proc_force_signal(proc_get(child_pid), SIGUSR1);
  KEXPECT_EQ(child_pid, proc_wait(0x0));
  KEXPECT_GE(async_args.result, -EINTR);
  KEXPECT_EQ(0, vfs_close(s1));
  KEXPECT_EQ(0, vfs_close(s2));

  KTEST_BEGIN("sockets (AF_UNIX): vfs_read() and vfs_write()");
  make_connected_pair(listen_sock, &s1, &s2);
  KEXPECT_EQ(5, vfs_write(s1, "abcde", 5));
  kmemset(buf, 0, 10);
  KEXPECT_EQ(5, vfs_read(s2, buf, 50));
  KEXPECT_STREQ("abcde", buf);
  KEXPECT_EQ(0, vfs_close(s1));
  KEXPECT_EQ(0, vfs_close(s2));

  // TODO(aoates): things to test for basic r/w:
  //  - duplicate close tests with shutdown
  //  - recv/send on different types of unconnected sockets

  KEXPECT_EQ(0, vfs_unlink(kServerPath));
  KEXPECT_EQ(0, vfs_close(listen_sock));
  kfree(bigbuf);
}

static void send_recv_addr_test(void) {
  const char kServerPath[] = "_server_sock";
  KTEST_BEGIN("net_sendto(): address ignored");
  int listen_sock = create_listening_socket(kServerPath, 5);
  KEXPECT_GE(listen_sock, 0);
  int s1, s2;
  make_connected_pair(listen_sock, &s1, &s2);

  struct sockaddr_un addr;
  addr.sun_family = AF_UNIX;
  kstrcpy(addr.sun_path, kServerPath);
  KEXPECT_EQ(2,
             net_sendto(s1, "ab", 2, 0, (struct sockaddr*)&addr, sizeof(addr)));
  kstrcpy(addr.sun_path, "other-path");
  KEXPECT_EQ(1,
             net_sendto(s1, "c", 1, 0, (struct sockaddr*)&addr, sizeof(addr)));
  addr.sun_family = 1234;
  KEXPECT_EQ(1,
             net_sendto(s1, "d", 1, 0, (struct sockaddr*)&addr, sizeof(addr)));
  KEXPECT_EQ(1, net_sendto(s1, "e", 1, 0, (struct sockaddr*)&addr, 1));
  KEXPECT_EQ(1, net_sendto(s1, "f", 1, 0, 0x0, 15));
  KEXPECT_EQ(1, net_sendto(s1, "g", 1, 0, 0x0, 0));

  KTEST_BEGIN("net_recvfrom(): zeroes out the address");
  kmemset(&addr, 1, sizeof(addr));
  socklen_t addr_len = sizeof(addr);
  char buf[5];
  KEXPECT_EQ(1,
             net_recvfrom(s2, buf, 1, 0, (struct sockaddr*)&addr, &addr_len));
  KEXPECT_EQ(0, addr_len);
  addr_len = 0;
  KEXPECT_EQ(1,
             net_recvfrom(s2, buf, 1, 0, (struct sockaddr*)&addr, &addr_len));
  KEXPECT_EQ(0, addr_len);
  addr_len = 5;
  KEXPECT_EQ(1, net_recvfrom(s2, buf, 1, 0, NULL, &addr_len));
  KEXPECT_EQ(1, net_recvfrom(s2, buf, 1, 0, NULL, NULL));

  KEXPECT_EQ(0, vfs_close(s1));
  KEXPECT_EQ(0, vfs_close(s2));

  KEXPECT_EQ(0, vfs_unlink(kServerPath));
  KEXPECT_EQ(0, vfs_close(listen_sock));
}

static void send_recv_bad_args_test(void) {
  const char kServerPath[] = "_server_sock";
  KTEST_BEGIN("net_send(): bad fd");
  int listen_sock = create_listening_socket(kServerPath, 5);
  KEXPECT_GE(listen_sock, 0);
  int s1, s2;
  make_connected_pair(listen_sock, &s1, &s2);

  char buf[5];
  KEXPECT_EQ(-EBADF, net_send(-5, buf, 5, 0));

  KTEST_BEGIN("net_send(): non-socket fd");
  int pipe_fds[2];
  KEXPECT_EQ(0, vfs_pipe(pipe_fds));
  KEXPECT_EQ(-ENOTSOCK, net_send(pipe_fds[0], buf, 5, 0));

  KTEST_BEGIN("net_send(): bad buffer");
  KEXPECT_EQ(-EINVAL, net_send(s1, NULL, 5, 0));

  KTEST_BEGIN("net_send(): bad flags");
  KEXPECT_EQ(-EINVAL, net_send(s1, buf, 5, 5));

  KTEST_BEGIN("net_recv(): bad fd");
  KEXPECT_EQ(-EBADF, net_recv(-5, buf, 5, 0));

  KTEST_BEGIN("net_recv(): non-socket fd");
  KEXPECT_EQ(-ENOTSOCK, net_recv(pipe_fds[0], buf, 5, 0));

  KTEST_BEGIN("net_recv(): bad buffer");
  KEXPECT_EQ(-EINVAL, net_recv(s1, NULL, 5, 0));

  KTEST_BEGIN("net_recv(): bad flags");
  KEXPECT_EQ(-EINVAL, net_recv(s1, buf, 5, 5));

  KEXPECT_EQ(0, vfs_close(pipe_fds[0]));
  KEXPECT_EQ(0, vfs_close(pipe_fds[1]));
  KEXPECT_EQ(0, vfs_close(s1));
  KEXPECT_EQ(0, vfs_close(s2));

  KEXPECT_EQ(0, vfs_unlink(kServerPath));
  KEXPECT_EQ(0, vfs_close(listen_sock));
}

static void nonblock_test(void) {
  const char kServerPath[] = "_server_sock";
  KTEST_BEGIN("net_accept(AF_UNIX): O_NONBLOCK");
  int listen_sock = create_listening_socket(kServerPath, 5);
  KEXPECT_GE(listen_sock, 0);

  vfs_make_nonblock(listen_sock);
  KEXPECT_EQ(-EAGAIN, net_accept(listen_sock, NULL, NULL));
  KEXPECT_EQ(-EAGAIN, net_accept(listen_sock, NULL, NULL));

  int s1 = net_socket(AF_UNIX, SOCK_STREAM, 0);
  KEXPECT_GE(s1, 0);
  KEXPECT_EQ(0, do_connect(s1, kServerPath));

  int s2 = net_accept(listen_sock, NULL, NULL);
  KEXPECT_GE(s2, 0);
  KEXPECT_EQ(-EAGAIN, net_accept(listen_sock, NULL, NULL));

  KTEST_BEGIN("net_recv(AF_UNIX): O_NONBLOCK");
  vfs_make_nonblock(s1);
  char buf[10];
  KEXPECT_EQ(-EAGAIN, net_recv(s1, buf, 10, 0));
  KEXPECT_EQ(-EAGAIN, net_recv(s1, buf, 10, 0));
  KEXPECT_EQ(5, net_send(s2, "abcde", 5, 0));
  KEXPECT_EQ(5, net_recv(s1, buf, 10, 0));
  KEXPECT_EQ(-EAGAIN, net_recv(s1, buf, 10, 0));

  KTEST_BEGIN("net_send(AF_UNIX): O_NONBLOCK");
  void* bigbuf = kmalloc(1024);
  int result;
  do {
    result = net_send(s1, bigbuf, 1024, 0);
  } while (result > 0);
  KEXPECT_EQ(-EAGAIN, result);
  KEXPECT_EQ(-EAGAIN, net_send(s1, buf, 10, 0));
  KEXPECT_EQ(5, net_recv(s2, buf, 5, 0));
  KEXPECT_EQ(5, net_send(s1, bigbuf, 1024, 0));
  KEXPECT_EQ(-EAGAIN, net_send(s1, buf, 10, 0));

  KTEST_BEGIN("net_recv(AF_UNIX): O_NONBLOCK but shutdown");
  KEXPECT_EQ(0, vfs_close(s2));
  KEXPECT_EQ(0, net_recv(s1, buf, 10, 0));

  KTEST_BEGIN("net_send(AF_UNIX): O_NONBLOCK but shutdown");
  KEXPECT_EQ(-EPIPE, net_send(s1, buf, 10, 0));
  proc_suppress_signal(proc_current(), SIGPIPE);

  // TODO(aoates): test the above after shutdown() once that's implemented.

  kfree(bigbuf);
  KEXPECT_EQ(0, vfs_close(s1));

  KEXPECT_EQ(0, vfs_unlink(kServerPath));
  KEXPECT_EQ(0, vfs_close(listen_sock));
}

static void shutdown_test(void) {
  const char kServerPath[] = "_server_sock";
  KTEST_BEGIN("sockets (AF_UNIX): s2.shutdown(SHUT_WR) then s1.recv()");
  int listen_sock = create_listening_socket(kServerPath, 5);
  KEXPECT_GE(listen_sock, 0);
  int s1, s2;
  make_connected_pair(listen_sock, &s1, &s2);

  char buf[100];
  KEXPECT_EQ(3, net_send(s2, "abc", 3, 0));
  KEXPECT_EQ(1, net_send(s1, "d", 1, 0));
  KEXPECT_EQ(0, net_shutdown(s2, SHUT_WR));
  KEXPECT_EQ(2, net_recv(s1, buf, 2, 0));
  KEXPECT_EQ(1, net_recv(s1, buf, 10, 0));
  KEXPECT_EQ(0, net_recv(s1, buf, 10, 0));
  KEXPECT_EQ(0, net_recv(s1, buf, 10, 0));

  KTEST_BEGIN("sockets (AF_UNIX): s2.shutdown(SHUT_WR) then s2.send()");
  KEXPECT_EQ(-EPIPE, net_send(s2, "abc", 3, 0));
  KEXPECT_EQ(true, has_sigpipe());
  proc_suppress_signal(proc_current(), SIGPIPE);

  KTEST_BEGIN(
      "sockets (AF_UNIX): s2.shutdown(SHUT_WR) then s1.send()/s2.recv() "
      "(opposite dir)");
  KEXPECT_EQ(2, net_send(s1, "ef", 2, 0));
  KEXPECT_EQ(3, net_recv(s2, buf, 10, 0));
  buf[3] = '\0';
  KEXPECT_STREQ("def", buf);
  KEXPECT_EQ(0, vfs_close(s1));
  KEXPECT_EQ(0, vfs_close(s2));

  KTEST_BEGIN("sockets (AF_UNIX): s2.shutdown(SHUT_RDWR) then s1.recv()");
  make_connected_pair(listen_sock, &s1, &s2);
  KEXPECT_EQ(3, net_send(s2, "abc", 3, 0));
  KEXPECT_EQ(0, net_shutdown(s2, SHUT_RDWR));
  KEXPECT_EQ(3, net_recv(s1, buf, 10, 0));
  KEXPECT_EQ(0, net_recv(s1, buf, 10, 0));
  KEXPECT_EQ(0, net_recv(s1, buf, 10, 0));

  KTEST_BEGIN("sockets (AF_UNIX): s2.shutdown(SHUT_RDWR) then s2.send()");
  KEXPECT_EQ(-EPIPE, net_send(s2, "abc", 3, 0));
  KEXPECT_EQ(true, has_sigpipe());
  proc_suppress_signal(proc_current(), SIGPIPE);
  KEXPECT_EQ(0, vfs_close(s1));
  KEXPECT_EQ(0, vfs_close(s2));

  KTEST_BEGIN("sockets (AF_UNIX): s1.shutdown(SHUT_RD) then s1.recv()");
  make_connected_pair(listen_sock, &s1, &s2);
  KEXPECT_EQ(3, net_send(s2, "abc", 3, 0));
  KEXPECT_EQ(0, net_shutdown(s1, SHUT_RD));
  // Pending data should be thrown away.
  KEXPECT_EQ(0, net_recv(s1, buf, 10, 0));
  KEXPECT_EQ(0, net_recv(s1, buf, 10, 0));

  KTEST_BEGIN("sockets (AF_UNIX): s1.shutdown(SHUT_RD) then s2.send()");
  KEXPECT_EQ(-EPIPE, net_send(s2, "abc", 3, 0));
  KEXPECT_EQ(true, has_sigpipe());
  proc_suppress_signal(proc_current(), SIGPIPE);

  KTEST_BEGIN(
      "sockets (AF_UNIX): s1.shutdown(SHUT_RD) then s1.send()/s2.recv() "
      "(opposite dir)");
  KEXPECT_EQ(3, net_send(s1, "abc", 3, 0));
  KEXPECT_EQ(3, net_recv(s2, buf, 10, 0));
  KEXPECT_EQ(0, vfs_close(s1));
  KEXPECT_EQ(0, vfs_close(s2));

  KTEST_BEGIN("sockets (AF_UNIX): s1.shutdown(SHUT_RDWR) then s1.recv()");
  make_connected_pair(listen_sock, &s1, &s2);
  KEXPECT_EQ(3, net_send(s2, "abc", 3, 0));
  KEXPECT_EQ(0, net_shutdown(s1, SHUT_RDWR));
  // Pending data should be thrown away.
  KEXPECT_EQ(0, net_recv(s1, buf, 10, 0));
  KEXPECT_EQ(0, net_recv(s1, buf, 10, 0));

  KTEST_BEGIN("sockets (AF_UNIX): s1.shutdown(SHUT_RDWR) then s2.send()");
  KEXPECT_EQ(-EPIPE, net_send(s2, "abc", 3, 0));
  KEXPECT_EQ(true, has_sigpipe());
  proc_suppress_signal(proc_current(), SIGPIPE);
  KEXPECT_EQ(0, vfs_close(s1));
  KEXPECT_EQ(0, vfs_close(s2));

  // Start blocking tests---shutdown() on other side during a blocking recv().
  KTEST_BEGIN(
      "sockets (AF_UNIX): s2.shutdown(SHUT_RD) during blocking s1.recv()");
  make_connected_pair(listen_sock, &s1, &s2);
  async_args_t async_args;
  async_args.sock = s1;
  async_args.buf = buf;
  async_args.len = 100;
  kmemset(buf, 0, 100);
  kthread_t thread = start_async(&recv_thread, &async_args);
  KEXPECT_EQ(false, kthread_is_done(thread));
  KEXPECT_EQ(0, net_shutdown(s2, SHUT_RD));
  for (int i = 0; i < 10; ++i) scheduler_yield();
  // Blocking recv() shouldn't return.
  KEXPECT_EQ(false, kthread_is_done(thread));

  KTEST_BEGIN(
      "sockets (AF_UNIX): s2.shutdown(SHUT_WR) during blocking s1.recv()");
  KEXPECT_EQ(0, net_shutdown(s2, SHUT_WR));
  kthread_join(thread);
  KEXPECT_EQ(0, async_args.result);
  KEXPECT_EQ(0, net_recv(s1, buf, 100, 0));
  KEXPECT_EQ(0, vfs_close(s1));
  KEXPECT_EQ(0, vfs_close(s2));

  KTEST_BEGIN(
      "sockets (AF_UNIX): s2.shutdown(SHUT_RDWR) during blocking s1.recv()");
  make_connected_pair(listen_sock, &s1, &s2);
  async_args.sock = s1;
  thread = start_async(&recv_thread, &async_args);
  KEXPECT_EQ(false, kthread_is_done(thread));
  KEXPECT_EQ(0, net_shutdown(s2, SHUT_RDWR));
  kthread_join(thread);
  KEXPECT_EQ(0, async_args.result);
  KEXPECT_EQ(0, net_recv(s1, buf, 100, 0));
  KEXPECT_EQ(0, vfs_close(s1));
  KEXPECT_EQ(0, vfs_close(s2));

  // Tests for shutdown() on _this_ side during a blocking recv().
  KTEST_BEGIN(
      "sockets (AF_UNIX): s1.shutdown(SHUT_WR) during blocking s1.recv()");
  make_connected_pair(listen_sock, &s1, &s2);
  async_args.sock = s1;
  thread = start_async(&recv_thread, &async_args);
  KEXPECT_EQ(false, kthread_is_done(thread));
  KEXPECT_EQ(0, net_shutdown(s1, SHUT_WR));
  for (int i = 0; i < 10; ++i) scheduler_yield();
  // Blocking recv() shouldn't return.
  KEXPECT_EQ(false, kthread_is_done(thread));

  KTEST_BEGIN(
      "sockets (AF_UNIX): s1.shutdown(SHUT_RD) during blocking s1.recv()");
  KEXPECT_EQ(0, net_shutdown(s1, SHUT_RD));
  kthread_join(thread);
  KEXPECT_EQ(0, async_args.result);
  KEXPECT_EQ(0, net_recv(s1, buf, 100, 0));
  KEXPECT_EQ(0, vfs_close(s1));
  KEXPECT_EQ(0, vfs_close(s2));

  KTEST_BEGIN(
      "sockets (AF_UNIX): s1.shutdown(SHUT_RDWR) during blocking s1.recv()");
  make_connected_pair(listen_sock, &s1, &s2);
  async_args.sock = s1;
  thread = start_async(&recv_thread, &async_args);
  KEXPECT_EQ(false, kthread_is_done(thread));
  KEXPECT_EQ(0, net_shutdown(s1, SHUT_RDWR));
  kthread_join(thread);
  KEXPECT_EQ(0, async_args.result);
  KEXPECT_EQ(0, net_recv(s1, buf, 100, 0));
  KEXPECT_EQ(0, vfs_close(s1));
  KEXPECT_EQ(0, vfs_close(s2));

  // Tests for shutdown() on other side during a blocking send().
  KTEST_BEGIN(
      "sockets (AF_UNIX): s2.shutdown(SHUT_WR) during blocking s1.send()");
  make_connected_pair(listen_sock, &s1, &s2);
  const int kBigBufSize = 32 * 1024;
  void* bigbuf = kmalloc(kBigBufSize);
  int max_send_buf = net_send(s1, bigbuf, kBigBufSize, 0);
  KEXPECT_GE(max_send_buf, 1024);
  async_args.sock = s1;
  thread = start_async(&send_thread, &async_args);
  KEXPECT_EQ(false, kthread_is_done(thread));
  KEXPECT_EQ(0, net_shutdown(s2, SHUT_WR));
  for (int i = 0; i < 10; ++i) scheduler_yield();
  // Blocking send() shouldn't return.
  KEXPECT_EQ(false, kthread_is_done(thread));

  KTEST_BEGIN(
      "sockets (AF_UNIX): s2.shutdown(SHUT_RD) during blocking s1.send()");
  KEXPECT_EQ(0, net_shutdown(s2, SHUT_RD));
  kthread_join(thread);
  KEXPECT_EQ(-EPIPE, async_args.result);
  KEXPECT_EQ(-EPIPE, net_send(s1, "a", 1, 0));
  proc_suppress_signal(proc_current(), SIGPIPE);
  KEXPECT_EQ(0, vfs_close(s1));
  KEXPECT_EQ(0, vfs_close(s2));

  KTEST_BEGIN(
      "sockets (AF_UNIX): s2.shutdown(SHUT_RDWR) during blocking s1.send()");
  make_connected_pair(listen_sock, &s1, &s2);
  max_send_buf = net_send(s1, bigbuf, kBigBufSize, 0);
  KEXPECT_GE(max_send_buf, 1024);
  async_args.sock = s1;
  thread = start_async(&send_thread, &async_args);
  KEXPECT_EQ(false, kthread_is_done(thread));
  KEXPECT_EQ(0, net_shutdown(s2, SHUT_RDWR));
  kthread_join(thread);
  KEXPECT_EQ(-EPIPE, async_args.result);
  proc_suppress_signal(proc_current(), SIGPIPE);
  KEXPECT_EQ(0, vfs_close(s1));
  KEXPECT_EQ(0, vfs_close(s2));

  // Tests for shutdown() on _this_ side during a blocking send().
  KTEST_BEGIN(
      "sockets (AF_UNIX): s1.shutdown(SHUT_RD) during blocking s1.send()");
  make_connected_pair(listen_sock, &s1, &s2);
  max_send_buf = net_send(s1, bigbuf, kBigBufSize, 0);
  KEXPECT_GE(max_send_buf, 1024);
  async_args.sock = s1;
  thread = start_async(&send_thread, &async_args);
  KEXPECT_EQ(false, kthread_is_done(thread));
  KEXPECT_EQ(0, net_shutdown(s1, SHUT_RD));
  for (int i = 0; i < 10; ++i) scheduler_yield();
  // Blocking recv() shouldn't return.
  KEXPECT_EQ(false, kthread_is_done(thread));

  KTEST_BEGIN(
      "sockets (AF_UNIX): s1.shutdown(SHUT_WR) during blocking s1.send()");
  KEXPECT_EQ(0, net_shutdown(s1, SHUT_WR));
  kthread_join(thread);
  KEXPECT_EQ(-EPIPE, async_args.result);
  proc_suppress_signal(proc_current(), SIGPIPE);
  KEXPECT_EQ(0, vfs_close(s1));
  KEXPECT_EQ(0, vfs_close(s2));

  KTEST_BEGIN(
      "sockets (AF_UNIX): s1.shutdown(SHUT_RDWR) during blocking s1.send()");
  make_connected_pair(listen_sock, &s1, &s2);
  max_send_buf = net_send(s1, bigbuf, kBigBufSize, 0);
  async_args.sock = s1;
  thread = start_async(&send_thread, &async_args);
  KEXPECT_EQ(false, kthread_is_done(thread));
  KEXPECT_EQ(0, net_shutdown(s1, SHUT_RDWR));
  kthread_join(thread);
  KEXPECT_EQ(-EPIPE, async_args.result);
  proc_suppress_signal(proc_current(), SIGPIPE);
  KEXPECT_EQ(0, vfs_close(s1));
  KEXPECT_EQ(0, vfs_close(s2));

  kfree(bigbuf);
  KEXPECT_EQ(0, vfs_unlink(kServerPath));
  KEXPECT_EQ(0, vfs_close(listen_sock));
}

static void double_shutdown_test(void) {
  const char kServerPath[] = "_server_sock";
  KTEST_BEGIN("net_shutdown(AF_UNIX): double shutdown");
  int listen_sock = create_listening_socket(kServerPath, 5);
  KEXPECT_GE(listen_sock, 0);
  int s1, s2;
  make_connected_pair(listen_sock, &s1, &s2);

  KEXPECT_EQ(0, net_shutdown(s1, SHUT_RD));
  KEXPECT_EQ(-ENOTCONN, net_shutdown(s1, SHUT_RD));
  KEXPECT_EQ(0, net_shutdown(s1, SHUT_WR));
  KEXPECT_EQ(-ENOTCONN, net_shutdown(s1, SHUT_WR));
  KEXPECT_EQ(-ENOTCONN, net_shutdown(s1, SHUT_RDWR));
  KEXPECT_EQ(0, vfs_close(s1));
  KEXPECT_EQ(0, vfs_close(s2));

  KTEST_BEGIN("net_shutdown(AF_UNIX): shutdown after other side has shutdown");
  make_connected_pair(listen_sock, &s1, &s2);
  KEXPECT_EQ(0, net_shutdown(s1, SHUT_RD));
  KEXPECT_EQ(0, net_shutdown(s2, SHUT_RD));
  KEXPECT_EQ(-ENOTCONN, net_shutdown(s2, SHUT_WR));
  KEXPECT_EQ(-ENOTCONN, net_shutdown(s2, SHUT_RDWR));
  KEXPECT_EQ(0, vfs_close(s1));
  KEXPECT_EQ(0, vfs_close(s2));

  make_connected_pair(listen_sock, &s1, &s2);
  KEXPECT_EQ(0, net_shutdown(s1, SHUT_WR));
  KEXPECT_EQ(0, net_shutdown(s2, SHUT_WR));
  KEXPECT_EQ(-ENOTCONN, net_shutdown(s2, SHUT_RD));
  KEXPECT_EQ(-ENOTCONN, net_shutdown(s2, SHUT_RDWR));
  KEXPECT_EQ(0, vfs_close(s1));
  KEXPECT_EQ(0, vfs_close(s2));

  KTEST_BEGIN("net_shutdown(AF_UNIX): shutdown after other side has closed");
  make_connected_pair(listen_sock, &s1, &s2);
  KEXPECT_EQ(0, vfs_close(s1));
  KEXPECT_EQ(-ENOTCONN, net_shutdown(s2, SHUT_RD));
  KEXPECT_EQ(-ENOTCONN, net_shutdown(s2, SHUT_WR));
  KEXPECT_EQ(-ENOTCONN, net_shutdown(s2, SHUT_RDWR));
  KEXPECT_EQ(0, vfs_close(s2));

  KEXPECT_EQ(0, vfs_unlink(kServerPath));
  KEXPECT_EQ(0, vfs_close(listen_sock));
}

static void shutdown_error_test(void) {
  const char kServerPath[] = "_socket_server_path";

  KTEST_BEGIN("net_shutdown(AF_UNIX): on new socket");
  int sock = net_socket(AF_UNIX, SOCK_STREAM, 0);
  KEXPECT_EQ(-ENOTCONN, net_shutdown(sock, SHUT_RD));
  KEXPECT_EQ(-ENOTCONN, net_shutdown(sock, SHUT_WR));
  KEXPECT_EQ(-ENOTCONN, net_shutdown(sock, SHUT_RDWR));
  KEXPECT_EQ(0, vfs_close(sock));

  KTEST_BEGIN("net_shutdown(AF_UNIX): on only-bound socket");
  sock = create_bound_socket(kServerPath);
  KEXPECT_GE(sock, 0);
  KEXPECT_EQ(-ENOTCONN, net_shutdown(sock, SHUT_RD));
  KEXPECT_EQ(-ENOTCONN, net_shutdown(sock, SHUT_WR));
  KEXPECT_EQ(-ENOTCONN, net_shutdown(sock, SHUT_RDWR));
  KEXPECT_EQ(0, vfs_close(sock));
  vfs_unlink(kServerPath);

  KTEST_BEGIN("net_shutdown(AF_UNIX): on listening socket");
  sock = create_listening_socket(kServerPath, 5);
  KEXPECT_GE(sock, 0);
  KEXPECT_EQ(-ENOTCONN, net_shutdown(sock, SHUT_RD));
  KEXPECT_EQ(-ENOTCONN, net_shutdown(sock, SHUT_WR));
  KEXPECT_EQ(-ENOTCONN, net_shutdown(sock, SHUT_RDWR));
  KEXPECT_EQ(0, vfs_close(sock));
  vfs_unlink(kServerPath);

  KTEST_BEGIN("net_shutdown(AF_UNIX): on bad fd");
  KEXPECT_EQ(-EBADF, net_shutdown(-5, SHUT_RD));
  KEXPECT_EQ(-EBADF, net_shutdown(sock, SHUT_RD));

  KTEST_BEGIN("net_shutdown(AF_UNIX): on non-socket fd");
  int pipe_fds[2];
  KEXPECT_EQ(0, vfs_pipe(pipe_fds));
  KEXPECT_EQ(-ENOTSOCK, net_shutdown(pipe_fds[0], SHUT_RD));
  vfs_close(pipe_fds[0]);
  vfs_close(pipe_fds[1]);

  KTEST_BEGIN("net_shutdown(AF_UNIX): bad how argument");
  sock = net_socket(AF_UNIX, SOCK_STREAM, 0);
  KEXPECT_EQ(-EINVAL, net_shutdown(pipe_fds[0], -1));
  KEXPECT_EQ(-EINVAL, net_shutdown(pipe_fds[0], 5));
  KEXPECT_EQ(0, vfs_close(sock));
}

static int do_poll(int fd) {
  struct apos_pollfd pfd;
  pfd.fd = fd;
  pfd.events = KPOLLIN | KPOLLRDNORM | KPOLLRDBAND | KPOLLPRI | KPOLLOUT |
               KPOLLWRNORM | KPOLLWRBAND | KPOLLERR | KPOLLHUP | KPOLLNVAL;
  pfd.revents = 0;
  int result = vfs_poll(&pfd, 1, 0);
  KEXPECT_GE(result, 0);
  return result ? pfd.revents : 0;
}

static void sock_unix_poll_test(void) {
  const char kServerPath[] = "_server_sock";
  KTEST_BEGIN("vfs_poll(): unbound AF_UNIX socket");
  int listen_sock = net_socket(AF_UNIX, SOCK_STREAM, 0);
  KEXPECT_GE(listen_sock, 0);
  KEXPECT_EQ(0, do_poll(listen_sock));
  KEXPECT_EQ(0, vfs_close(listen_sock));

  KTEST_BEGIN("vfs_poll(): bound AF_UNIX socket");
  listen_sock = create_bound_socket(kServerPath);
  KEXPECT_EQ(0, do_poll(listen_sock));
  KEXPECT_EQ(0, vfs_close(listen_sock));
  vfs_unlink(kServerPath);

  KTEST_BEGIN("vfs_poll(): listening AF_UNIX socket (no connections)");
  listen_sock = create_listening_socket(kServerPath, 5);
  KEXPECT_GE(listen_sock, 0);
  KEXPECT_EQ(0, do_poll(listen_sock));

  KTEST_BEGIN("vfs_poll(): listening AF_UNIX socket (pending connection)");
  int s1 = net_socket(AF_UNIX, SOCK_STREAM, 0);
  KEXPECT_GE(s1, 0);
  KEXPECT_EQ(0, do_connect(s1, kServerPath));
  KEXPECT_EQ(KPOLLIN | KPOLLRDNORM, do_poll(listen_sock));

  int s2 = net_accept(listen_sock, NULL, 0);
  KEXPECT_GE(s2, 0);
  KEXPECT_EQ(0, do_poll(listen_sock));

  KTEST_BEGIN("vfs_poll(): fresh connected sockets (AF_UNIX)");
  KEXPECT_EQ(KPOLLOUT | KPOLLWRNORM | KPOLLWRBAND, do_poll(s1));
  KEXPECT_EQ(KPOLLOUT | KPOLLWRNORM | KPOLLWRBAND, do_poll(s2));

  KTEST_BEGIN("vfs_poll(): data available (AF_UNIX)");
  KEXPECT_EQ(1, vfs_write(s1, "a", 1));
  KEXPECT_EQ(KPOLLOUT | KPOLLWRNORM | KPOLLWRBAND, do_poll(s1));
  KEXPECT_EQ(KPOLLIN | KPOLLRDNORM | KPOLLOUT | KPOLLWRNORM | KPOLLWRBAND,
             do_poll(s2));

  KTEST_BEGIN("vfs_poll(): filled buffer, can't send (AF_UNIX)");
  const int kBigBufSize = 32 * 1024;
  void* bigbuf = kmalloc(kBigBufSize);
  int max_send_buf = net_send(s1, bigbuf, kBigBufSize, 0);
  KEXPECT_GE(max_send_buf, 1024);
  KEXPECT_EQ(0, do_poll(s1));
  KEXPECT_EQ(KPOLLIN | KPOLLRDNORM | KPOLLOUT | KPOLLWRNORM | KPOLLWRBAND,
             do_poll(s2));

  KEXPECT_EQ(3, vfs_write(s2, "abc", 3));
  KEXPECT_EQ(KPOLLIN | KPOLLRDNORM, do_poll(s1));
  KEXPECT_EQ(KPOLLIN | KPOLLRDNORM | KPOLLOUT | KPOLLWRNORM | KPOLLWRBAND,
             do_poll(s2));

  // Drain the buffer a bit.
  net_recv(s2, bigbuf, 1000, 0);

  KTEST_BEGIN("vfs_poll(): after shutdown(SHUT_RD) (AF_UNIX)");
  KEXPECT_EQ(0, net_shutdown(s1, SHUT_RD));
  KEXPECT_EQ(KPOLLIN | KPOLLRDNORM | KPOLLOUT | KPOLLWRNORM | KPOLLWRBAND,
             do_poll(s1));
  KEXPECT_EQ(KPOLLIN | KPOLLRDNORM | KPOLLHUP, do_poll(s2));

  KTEST_BEGIN("vfs_poll(): after shutdown(SHUT_WR) (AF_UNIX)");
  KEXPECT_EQ(0, net_shutdown(s1, SHUT_WR));
  KEXPECT_EQ(KPOLLIN | KPOLLRDNORM | KPOLLHUP, do_poll(s1));
  KEXPECT_EQ(KPOLLIN | KPOLLRDNORM | KPOLLHUP, do_poll(s2));
  KEXPECT_EQ(0, vfs_close(s1));
  KEXPECT_EQ(0, vfs_close(s2));

  KTEST_BEGIN("vfs_poll(): after close() (AF_UNIX)");
  make_connected_pair(listen_sock, &s1, &s2);
  KEXPECT_EQ(3, net_send(s1, "abc", 3, 0));
  KEXPECT_EQ(0, vfs_close(s1));
  KEXPECT_EQ(KPOLLIN | KPOLLRDNORM | KPOLLHUP, do_poll(s2));
  KEXPECT_EQ(3, net_recv(s2, bigbuf, 100, 0));
  // Should get KPOLLIN even if there's not data.
  KEXPECT_EQ(KPOLLIN | KPOLLRDNORM | KPOLLHUP, do_poll(s2));
  KEXPECT_EQ(0, vfs_close(s2));

  kfree(bigbuf);
  KEXPECT_EQ(0, vfs_unlink(kServerPath));
  KEXPECT_EQ(0, vfs_close(listen_sock));
}

typedef struct {
  struct apos_pollfd pfd[2];
  int nfds;
  int result;
  kthread_queue_t started_queue;
  kthread_t thread;
} async_poll_args_t;

static void* do_async_poll(void* x) {
  async_poll_args_t* args = (async_poll_args_t*)x;
  scheduler_wake_all(&args->started_queue);
  args->result = vfs_poll(&args->pfd[0], args->nfds, -1);
  KEXPECT_GE(args->result, 0);
  return NULL;
}

static void start_async_poll_internal(async_poll_args_t* args) {
  kthread_queue_init(&args->started_queue);
  int result = proc_thread_create(&args->thread, &do_async_poll, args);
  KASSERT(result == 0);
  scheduler_wait_on(&args->started_queue);
  for (int i = 0; i < 5; ++i) scheduler_yield();
  KEXPECT_EQ(false, kthread_is_done(args->thread));
}

static void start_async_poll(async_poll_args_t* args, int fd,
                             short int events) {
  args->pfd[0].fd = fd;
  args->pfd[0].events = events;
  args->nfds = 1;
  start_async_poll_internal(args);
}

static void start_async_poll2(async_poll_args_t* args, int fd1, int fd2,
                              short int events) {
  args->pfd[0].fd = fd1;
  args->pfd[0].events = events;
  args->pfd[1].fd = fd2;
  args->pfd[1].events = events;
  args->nfds = 2;
  start_async_poll_internal(args);
}

static int finish_async_poll(async_poll_args_t* args) {
  kthread_join(args->thread);
  KEXPECT_GE(args->result, 0);
  return args->result ? args->pfd[0].revents : 0;
}

static void sock_unix_poll_blocking_test(void) {
  const char kServerPath[] = "_server_sock";
  KTEST_BEGIN("vfs_poll(): connect() triggers KPOLLIN while blocked (AF_UNIX)");
  int listen_sock = create_listening_socket(kServerPath, 5);
  KEXPECT_GE(listen_sock, 0);

  async_poll_args_t pa;
  start_async_poll(&pa, listen_sock, KPOLLIN);

  int s1 = net_socket(AF_UNIX, SOCK_STREAM, 0);
  KEXPECT_GE(s1, 0);
  KEXPECT_EQ(0, do_connect(s1, kServerPath));

  KEXPECT_EQ(KPOLLIN, finish_async_poll(&pa));

  // TODO(aoates): spin off a separate process so we can test event masking.
  // Need another process so we can send a signal to stop the accept() call.

  KTEST_BEGIN("vfs_poll(): data triggers KPOLLIN while blocked (AF_UNIX)");
  int s2 = net_accept(listen_sock, NULL, 0);
  KEXPECT_GE(s2, 0);

  start_async_poll(&pa, s1, KPOLLIN);
  KEXPECT_EQ(3, net_send(s2, "abc", 3, 0));
  KEXPECT_EQ(KPOLLIN, finish_async_poll(&pa));

  KTEST_BEGIN(
      "vfs_poll(): free buffer space triggers KPOLLOUT while blocked (AF_UNIX)");
  const int kBigBufSize = 32 * 1024;
  void* bigbuf = kmalloc(kBigBufSize);
  int max_send_buf = net_send(s2, bigbuf, kBigBufSize, 0);
  KEXPECT_GE(max_send_buf, 1024);

  start_async_poll(&pa, s2, KPOLLOUT);
  KEXPECT_EQ(3, net_recv(s1, bigbuf, 3, 0));
  KEXPECT_EQ(KPOLLOUT, finish_async_poll(&pa));

  KTEST_BEGIN(
      "vfs_poll(): shutdown(WR) triggers KPOLLIN on other socket (AF_UNIX)");
  KEXPECT_GE(net_recv(s1, bigbuf, kBigBufSize, 0), 0);  // Drain the buffer.
  start_async_poll(&pa, s1, KPOLLIN);
  KEXPECT_EQ(0, net_shutdown(s2, SHUT_WR));
  KEXPECT_EQ(KPOLLIN, finish_async_poll(&pa));
  KEXPECT_EQ(0, vfs_close(s1));
  KEXPECT_EQ(0, vfs_close(s2));

  KTEST_BEGIN(
      "vfs_poll(): shutdown(WR) triggers KPOLLHUP on same socket (AF_UNIX)");
  make_connected_pair(listen_sock, &s1, &s2);
  start_async_poll(&pa, s1, KPOLLIN);
  KEXPECT_EQ(0, net_shutdown(s1, SHUT_WR));
  KEXPECT_EQ(KPOLLHUP, finish_async_poll(&pa));
  KEXPECT_EQ(0, vfs_close(s1));
  KEXPECT_EQ(0, vfs_close(s2));

  KTEST_BEGIN(
      "vfs_poll(): shutdown(RD) triggers KPOLLIN on same socket (AF_UNIX)");
  make_connected_pair(listen_sock, &s1, &s2);
  start_async_poll(&pa, s1, KPOLLIN);
  KEXPECT_EQ(0, net_shutdown(s1, SHUT_RD));
  KEXPECT_EQ(KPOLLIN, finish_async_poll(&pa));
  KEXPECT_EQ(0, vfs_close(s1));
  KEXPECT_EQ(0, vfs_close(s2));

  // TODO(aoates): I don't think this is right.
  KTEST_BEGIN(
      "vfs_poll(): shutdown(RD) triggers KPOLLHUP on other socket (AF_UNIX)");
  make_connected_pair(listen_sock, &s1, &s2);
  start_async_poll(&pa, s1, KPOLLIN);
  KEXPECT_EQ(0, net_shutdown(s2, SHUT_RD));
  KEXPECT_EQ(KPOLLHUP, finish_async_poll(&pa));
  KEXPECT_EQ(0, vfs_close(s1));
  KEXPECT_EQ(0, vfs_close(s2));

  KTEST_BEGIN("vfs_poll(): close() triggers KPOLLHUP on other socket (AF_UNIX)");
  make_connected_pair(listen_sock, &s1, &s2);
  start_async_poll(&pa, s1, KPOLLIN);
  KEXPECT_EQ(0, vfs_close(s2));
  KEXPECT_EQ(KPOLLIN | KPOLLHUP, finish_async_poll(&pa));
  KEXPECT_EQ(0, vfs_close(s1));

  kfree(bigbuf);
  KEXPECT_EQ(0, vfs_unlink(kServerPath));
  KEXPECT_EQ(0, vfs_close(listen_sock));
}

// Test what happens when we close() a socket while there's an outstanding poll
// on it.
static void sock_unix_close_during_poll_test(void) {
  const char kServerPath[] = "_server_sock";
  KTEST_BEGIN("vfs_poll(): close socket while poll is pending");
  int listen_sock = create_listening_socket(kServerPath, 5);
  KEXPECT_GE(listen_sock, 0);

  int s1, s2;
  make_connected_pair(listen_sock, &s1, &s2);

  // Do an async poll with 2 fds.  The listen FD is the one we'll close.  The
  // other fd (s1) is what we'll use to actually wake up the poll (not strictly
  // necessary, but makes the error case clearer).
  async_poll_args_t pa;
  start_async_poll2(&pa, listen_sock, s1, KPOLLIN);

  KEXPECT_EQ(0, vfs_close(listen_sock));
  KEXPECT_EQ(2, net_send(s2, "ab", 2, 0));

  kthread_join(pa.thread);
  KEXPECT_EQ(2, pa.result);
  KEXPECT_EQ(KPOLLNVAL, pa.pfd[0].revents);
  KEXPECT_EQ(KPOLLIN, pa.pfd[1].revents);

  vfs_close(s1);
  vfs_close(s2);
  KEXPECT_EQ(0, vfs_unlink(kServerPath));
}

static void sockname_test(void) {
  const char kClientPath[] = "_socket_client_path";
  const char kServerPath[] = "_socket_server_path";

  struct sockaddr_un server_addr;
  server_addr.sun_family = AF_UNIX;
  kstrcpy(server_addr.sun_path, kServerPath);

  struct sockaddr_un client_addr;
  client_addr.sun_family = AF_UNIX;
  kstrcpy(client_addr.sun_path, kClientPath);

  KTEST_BEGIN("net_getsockname(AF_UNIX): unbound socket");
  int server_sock = net_socket(AF_UNIX, SOCK_STREAM, 0);
  KEXPECT_GE(server_sock, 0);

  struct sockaddr_un result_addr;
  KEXPECT_EQ(0, net_getsockname(server_sock, (struct sockaddr*)&result_addr));
  KEXPECT_EQ(AF_UNIX, result_addr.sun_family);
  KEXPECT_STREQ("", result_addr.sun_path);


  KTEST_BEGIN("net_getpeername(AF_UNIX): unbound socket");
  KEXPECT_EQ(-ENOTCONN,
             net_getpeername(server_sock, (struct sockaddr*)&result_addr));


  KTEST_BEGIN("net_getsockname(AF_UNIX): bound socket");
  KEXPECT_EQ(0, net_bind(server_sock, (struct sockaddr*)&server_addr,
                         sizeof(server_addr)));
  kmemset(&result_addr, 0xff, sizeof(struct sockaddr_un));
  KEXPECT_EQ(0, net_getsockname(server_sock, (struct sockaddr*)&result_addr));
  KEXPECT_EQ(AF_UNIX, result_addr.sun_family);
  KEXPECT_STREQ(kServerPath, result_addr.sun_path);

  KTEST_BEGIN("net_getpeername(AF_UNIX): bound socket");
  KEXPECT_EQ(-ENOTCONN,
             net_getpeername(server_sock, (struct sockaddr*)&result_addr));

  KTEST_BEGIN("net_getsockname(AF_UNIX): connected socket");
  KEXPECT_EQ(0, net_listen(server_sock, 5));

  int client_sock = net_socket(AF_UNIX, SOCK_STREAM, 0);
  KEXPECT_GE(client_sock, 0);
  KEXPECT_EQ(0, net_bind(client_sock, (struct sockaddr*)&client_addr,
                         sizeof(client_addr)));
  KEXPECT_EQ(0, net_connect(client_sock, (struct sockaddr*)&server_addr,
                            sizeof(server_addr)));

  int accepted_sock = net_accept(server_sock, NULL, 0);
  KEXPECT_GE(accepted_sock, 0);

  KEXPECT_EQ(0, net_getsockname(accepted_sock, (struct sockaddr*)&result_addr));
  KEXPECT_EQ(AF_UNIX, result_addr.sun_family);
  KEXPECT_STREQ(kServerPath, result_addr.sun_path);

  KEXPECT_EQ(0, net_getsockname(client_sock, (struct sockaddr*)&result_addr));
  KEXPECT_STREQ(kClientPath, result_addr.sun_path);

  KTEST_BEGIN("net_getpeername(AF_UNIX): connected socket");
  KEXPECT_EQ(0, net_getpeername(accepted_sock, (struct sockaddr*)&result_addr));
  KEXPECT_EQ(AF_UNIX, result_addr.sun_family);
  KEXPECT_STREQ(kClientPath, result_addr.sun_path);

  KEXPECT_EQ(0, net_getpeername(client_sock, (struct sockaddr*)&result_addr));
  KEXPECT_STREQ(kServerPath, result_addr.sun_path);

  KEXPECT_EQ(0, vfs_close(accepted_sock));
  KEXPECT_EQ(0, vfs_close(client_sock));
  KEXPECT_EQ(0, vfs_close(server_sock));
  KEXPECT_EQ(0, vfs_unlink(kServerPath));
  KEXPECT_EQ(0, vfs_unlink(kClientPath));
}

void socket_unix_test(void) {
  KTEST_SUITE_BEGIN("Socket (Unix Domain)");
  block_cache_clear_unpinned();
  const int initial_cache_size = vfs_cache_size();

  create_test();
  bind_test();
  listen_test();
  connect_test();
  connect_backlog_test();
  accept_blocking_test();
  send_recv_test();
  send_recv_addr_test();
  send_recv_bad_args_test();
  nonblock_test();
  shutdown_test();
  double_shutdown_test();
  shutdown_error_test();
  sock_unix_poll_test();
  sock_unix_poll_blocking_test();
  sock_unix_close_during_poll_test();
  sockname_test();

  KTEST_BEGIN("vfs: vnode leak verification");
  KEXPECT_EQ(initial_cache_size, vfs_cache_size());
}
