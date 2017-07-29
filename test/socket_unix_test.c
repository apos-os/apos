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
#include "proc/kthread.h"
#include "proc/fork.h"
#include "proc/scheduler.h"
#include "proc/umask.h"
#include "proc/user.h"
#include "proc/wait.h"
#include "test/ktest.h"
#include "test/vfs_test_util.h"
#include "user/include/apos/errors.h"
#include "user/include/apos/net/socket/unix.h"
#include "vfs/pipe.h"
#include "vfs/vfs.h"
#include "vfs/vfs_test_util.h"

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
  //  - non-blocking connect
  //  - bind on connected socket
  //  - accept() blocks until connect()
  //  - connect interrupted by signal
  //  - accept interrupted by signal
  //  - forked sockets
  //  - write on disconnected socket (closed) -> SIGPIPE (is this POSIX?)
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

void socket_unix_test(void) {
  KTEST_SUITE_BEGIN("Socket (Unix Domain)");
  block_cache_clear_unpinned();
  const int initial_cache_size = vfs_cache_size();

  create_test();
  bind_test();
  listen_test();
  connect_test();
  connect_backlog_test();

  KTEST_BEGIN("vfs: vnode leak verification");
  KEXPECT_EQ(initial_cache_size, vfs_cache_size());
}
