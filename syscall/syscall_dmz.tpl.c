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

#include "common/errno.h"
#include "common/kstring.h"
#include "common/time.h"
#include "dev/termios.h"
#include "memory/kmalloc.h"
#include "memory/mmap.h"
#include "net/socket/socket.h"
#include "proc/alarm.h"
#include "proc/futex.h"
#include "proc/group.h"
#include "proc/limit.h"
#include "proc/process.h"
#include "proc/session.h"
#include "proc/signal/signal.h"
#include "proc/sleep.h"
#include "proc/tcgroup.h"
#include "proc/umask.h"
#include "proc/user.h"
#include "proc/user_thread.h"
#include "proc/wait.h"
#include "syscall/dmz.h"
#include "syscall/execve_wrapper.h"
#include "syscall/fork.h"
#include "syscall/test.h"
#include "syscall/wrappers.h"
#include "syscall/wrappers32.h"
#include "test/kernel_tests.h"
#include "vfs/mount.h"
#include "vfs/pipe.h"
#include "vfs/poll.h"
#include "vfs/vfs.h"

long SYSCALL_DMZ_syscall_test(long arg1, long arg2, long arg3, long arg4,
                              long arg5, long arg6) {
  int result;

  result = do_syscall_test(arg1, arg2, arg3, arg4, arg5, arg6);

  // TODO(aoates): this should only copy the written bytes, not the full kernel
  // buffer (e.g. in a read() syscall).

  goto cleanup;  // Make the compiler happy if cleanup is otherwise unused.

cleanup:

  return result;
}

int SYSCALL_DMZ_open(const char* path, int flags, apos_mode_t mode) {
  const char* KERNEL_path = 0x0;

  const int SIZE_path = syscall_verify_string(path);
  if (SIZE_path < 0) return SIZE_path;

  KERNEL_path = (const char*)kmalloc(SIZE_path);

  if (!KERNEL_path) {
    if (KERNEL_path) kfree((void*)KERNEL_path);

    return -ENOMEM;
  }

  int result;
  if (path) {
    result = syscall_copy_from_user(path, (void*)KERNEL_path, SIZE_path);
    if (result) goto cleanup;
  }

  result = vfs_open(KERNEL_path, flags, mode);

  // TODO(aoates): this should only copy the written bytes, not the full kernel
  // buffer (e.g. in a read() syscall).

  goto cleanup;  // Make the compiler happy if cleanup is otherwise unused.

cleanup:
  if (KERNEL_path) kfree((void*)KERNEL_path);

  return result;
}

int SYSCALL_DMZ_close(int fd) {
  int result;

  result = vfs_close(fd);

  // TODO(aoates): this should only copy the written bytes, not the full kernel
  // buffer (e.g. in a read() syscall).

  goto cleanup;  // Make the compiler happy if cleanup is otherwise unused.

cleanup:

  return result;
}

int SYSCALL_DMZ_dup(int fd) {
  int result;

  result = vfs_dup(fd);

  // TODO(aoates): this should only copy the written bytes, not the full kernel
  // buffer (e.g. in a read() syscall).

  goto cleanup;  // Make the compiler happy if cleanup is otherwise unused.

cleanup:

  return result;
}

int SYSCALL_DMZ_dup2(int fd1, int fd2) {
  int result;

  result = vfs_dup2(fd1, fd2);

  // TODO(aoates): this should only copy the written bytes, not the full kernel
  // buffer (e.g. in a read() syscall).

  goto cleanup;  // Make the compiler happy if cleanup is otherwise unused.

cleanup:

  return result;
}

int SYSCALL_DMZ_mkdir(const char* path, apos_mode_t mode) {
  const char* KERNEL_path = 0x0;

  const int SIZE_path = syscall_verify_string(path);
  if (SIZE_path < 0) return SIZE_path;

  KERNEL_path = (const char*)kmalloc(SIZE_path);

  if (!KERNEL_path) {
    if (KERNEL_path) kfree((void*)KERNEL_path);

    return -ENOMEM;
  }

  int result;
  if (path) {
    result = syscall_copy_from_user(path, (void*)KERNEL_path, SIZE_path);
    if (result) goto cleanup;
  }

  result = vfs_mkdir(KERNEL_path, mode);

  // TODO(aoates): this should only copy the written bytes, not the full kernel
  // buffer (e.g. in a read() syscall).

  goto cleanup;  // Make the compiler happy if cleanup is otherwise unused.

cleanup:
  if (KERNEL_path) kfree((void*)KERNEL_path);

  return result;
}

int SYSCALL_DMZ_mknod(const char* path, apos_mode_t mode, apos_dev_t dev) {
  const char* KERNEL_path = 0x0;

  const int SIZE_path = syscall_verify_string(path);
  if (SIZE_path < 0) return SIZE_path;

  KERNEL_path = (const char*)kmalloc(SIZE_path);

  if (!KERNEL_path) {
    if (KERNEL_path) kfree((void*)KERNEL_path);

    return -ENOMEM;
  }

  int result;
  if (path) {
    result = syscall_copy_from_user(path, (void*)KERNEL_path, SIZE_path);
    if (result) goto cleanup;
  }

  result = vfs_mknod(KERNEL_path, mode, dev);

  // TODO(aoates): this should only copy the written bytes, not the full kernel
  // buffer (e.g. in a read() syscall).

  goto cleanup;  // Make the compiler happy if cleanup is otherwise unused.

cleanup:
  if (KERNEL_path) kfree((void*)KERNEL_path);

  return result;
}

int SYSCALL_DMZ_rmdir(const char* path) {
  const char* KERNEL_path = 0x0;

  const int SIZE_path = syscall_verify_string(path);
  if (SIZE_path < 0) return SIZE_path;

  KERNEL_path = (const char*)kmalloc(SIZE_path);

  if (!KERNEL_path) {
    if (KERNEL_path) kfree((void*)KERNEL_path);

    return -ENOMEM;
  }

  int result;
  if (path) {
    result = syscall_copy_from_user(path, (void*)KERNEL_path, SIZE_path);
    if (result) goto cleanup;
  }

  result = vfs_rmdir(KERNEL_path);

  // TODO(aoates): this should only copy the written bytes, not the full kernel
  // buffer (e.g. in a read() syscall).

  goto cleanup;  // Make the compiler happy if cleanup is otherwise unused.

cleanup:
  if (KERNEL_path) kfree((void*)KERNEL_path);

  return result;
}

int SYSCALL_DMZ_link(const char* path1, const char* path2) {
  const char* KERNEL_path1 = 0x0;
  const char* KERNEL_path2 = 0x0;

  const int SIZE_path1 = syscall_verify_string(path1);
  if (SIZE_path1 < 0) return SIZE_path1;
  const int SIZE_path2 = syscall_verify_string(path2);
  if (SIZE_path2 < 0) return SIZE_path2;

  KERNEL_path1 = (const char*)kmalloc(SIZE_path1);
  KERNEL_path2 = (const char*)kmalloc(SIZE_path2);

  if (!KERNEL_path1 || !KERNEL_path2) {
    if (KERNEL_path1) kfree((void*)KERNEL_path1);
    if (KERNEL_path2) kfree((void*)KERNEL_path2);

    return -ENOMEM;
  }

  int result;
  if (path1) {
    result = syscall_copy_from_user(path1, (void*)KERNEL_path1, SIZE_path1);
    if (result) goto cleanup;
  }
  if (path2) {
    result = syscall_copy_from_user(path2, (void*)KERNEL_path2, SIZE_path2);
    if (result) goto cleanup;
  }

  result = vfs_link(KERNEL_path1, KERNEL_path2);

  // TODO(aoates): this should only copy the written bytes, not the full kernel
  // buffer (e.g. in a read() syscall).

  goto cleanup;  // Make the compiler happy if cleanup is otherwise unused.

cleanup:
  if (KERNEL_path1) kfree((void*)KERNEL_path1);
  if (KERNEL_path2) kfree((void*)KERNEL_path2);

  return result;
}

int SYSCALL_DMZ_rename(const char* path1, const char* path2) {
  const char* KERNEL_path1 = 0x0;
  const char* KERNEL_path2 = 0x0;

  const int SIZE_path1 = syscall_verify_string(path1);
  if (SIZE_path1 < 0) return SIZE_path1;
  const int SIZE_path2 = syscall_verify_string(path2);
  if (SIZE_path2 < 0) return SIZE_path2;

  KERNEL_path1 = (const char*)kmalloc(SIZE_path1);
  KERNEL_path2 = (const char*)kmalloc(SIZE_path2);

  if (!KERNEL_path1 || !KERNEL_path2) {
    if (KERNEL_path1) kfree((void*)KERNEL_path1);
    if (KERNEL_path2) kfree((void*)KERNEL_path2);

    return -ENOMEM;
  }

  int result;
  if (path1) {
    result = syscall_copy_from_user(path1, (void*)KERNEL_path1, SIZE_path1);
    if (result) goto cleanup;
  }
  if (path2) {
    result = syscall_copy_from_user(path2, (void*)KERNEL_path2, SIZE_path2);
    if (result) goto cleanup;
  }

  result = vfs_rename(KERNEL_path1, KERNEL_path2);

  // TODO(aoates): this should only copy the written bytes, not the full kernel
  // buffer (e.g. in a read() syscall).

  goto cleanup;  // Make the compiler happy if cleanup is otherwise unused.

cleanup:
  if (KERNEL_path1) kfree((void*)KERNEL_path1);
  if (KERNEL_path2) kfree((void*)KERNEL_path2);

  return result;
}

int SYSCALL_DMZ_unlink(const char* path) {
  const char* KERNEL_path = 0x0;

  const int SIZE_path = syscall_verify_string(path);
  if (SIZE_path < 0) return SIZE_path;

  KERNEL_path = (const char*)kmalloc(SIZE_path);

  if (!KERNEL_path) {
    if (KERNEL_path) kfree((void*)KERNEL_path);

    return -ENOMEM;
  }

  int result;
  if (path) {
    result = syscall_copy_from_user(path, (void*)KERNEL_path, SIZE_path);
    if (result) goto cleanup;
  }

  result = vfs_unlink(KERNEL_path);

  // TODO(aoates): this should only copy the written bytes, not the full kernel
  // buffer (e.g. in a read() syscall).

  goto cleanup;  // Make the compiler happy if cleanup is otherwise unused.

cleanup:
  if (KERNEL_path) kfree((void*)KERNEL_path);

  return result;
}

int SYSCALL_DMZ_read(int fd, void* buf, size_t count) {
  void* KERNEL_buf = 0x0;

  const int CHECK_buf =
      syscall_verify_buffer(buf, count, 1 /* is_write */, 0 /* allow_null */);
  if (CHECK_buf < 0) return CHECK_buf;

  KERNEL_buf = (void*)kmalloc(count);

  if (!KERNEL_buf) {
    if (KERNEL_buf) kfree((void*)KERNEL_buf);

    return -ENOMEM;
  }

  int result;

  result = vfs_read(fd, KERNEL_buf, count);

  // TODO(aoates): this should only copy the written bytes, not the full kernel
  // buffer (e.g. in a read() syscall).
  if (buf) {
    int copy_result = syscall_copy_to_user(KERNEL_buf, buf, count);
    if (copy_result) {
      result = copy_result;
      goto cleanup;
    }
  }

  goto cleanup;  // Make the compiler happy if cleanup is otherwise unused.

cleanup:
  if (KERNEL_buf) kfree((void*)KERNEL_buf);

  return result;
}

int SYSCALL_DMZ_write(int fd, const void* buf, size_t count) {
  const void* KERNEL_buf = 0x0;

  const int CHECK_buf =
      syscall_verify_buffer(buf, count, 0 /* is_write */, 0 /* allow_null */);
  if (CHECK_buf < 0) return CHECK_buf;

  KERNEL_buf = (const void*)kmalloc(count);

  if (!KERNEL_buf) {
    if (KERNEL_buf) kfree((void*)KERNEL_buf);

    return -ENOMEM;
  }

  int result;
  if (buf) {
    result = syscall_copy_from_user(buf, (void*)KERNEL_buf, count);
    if (result) goto cleanup;
  }

  result = vfs_write(fd, KERNEL_buf, count);

  // TODO(aoates): this should only copy the written bytes, not the full kernel
  // buffer (e.g. in a read() syscall).

  goto cleanup;  // Make the compiler happy if cleanup is otherwise unused.

cleanup:
  if (KERNEL_buf) kfree((void*)KERNEL_buf);

  return result;
}

#if ARCH_IS_64_BIT
int SYSCALL_DMZ_getdents_32(int fd, kdirent_32_t* buf, int count) {
  kdirent_32_t* KERNEL_buf = 0x0;

  const int CHECK_buf =
      syscall_verify_buffer(buf, count, 1 /* is_write */, 0 /* allow_null */);
  if (CHECK_buf < 0) return CHECK_buf;

  KERNEL_buf = (kdirent_32_t*)kmalloc(count);

  if (!KERNEL_buf) {
    if (KERNEL_buf) kfree((void*)KERNEL_buf);

    return -ENOMEM;
  }

  int result;

  result = vfs_getdents_32(fd, KERNEL_buf, count);

  // TODO(aoates): this should only copy the written bytes, not the full kernel
  // buffer (e.g. in a read() syscall).
  if (buf) {
    int copy_result = syscall_copy_to_user(KERNEL_buf, buf, count);
    if (copy_result) {
      result = copy_result;
      goto cleanup;
    }
  }

  goto cleanup;  // Make the compiler happy if cleanup is otherwise unused.

cleanup:
  if (KERNEL_buf) kfree((void*)KERNEL_buf);

  return result;
}

#else
int SYSCALL_DMZ_getdents(int fd, kdirent_t* buf, int count) {
  kdirent_t* KERNEL_buf = 0x0;

  const int CHECK_buf =
      syscall_verify_buffer(buf, count, 1 /* is_write */, 0 /* allow_null */);
  if (CHECK_buf < 0) return CHECK_buf;

  KERNEL_buf = (kdirent_t*)kmalloc(count);

  if (!KERNEL_buf) {
    if (KERNEL_buf) kfree((void*)KERNEL_buf);

    return -ENOMEM;
  }

  int result;

  result = vfs_getdents(fd, KERNEL_buf, count);

  // TODO(aoates): this should only copy the written bytes, not the full kernel
  // buffer (e.g. in a read() syscall).
  if (buf) {
    int copy_result = syscall_copy_to_user(KERNEL_buf, buf, count);
    if (copy_result) {
      result = copy_result;
      goto cleanup;
    }
  }

  goto cleanup;  // Make the compiler happy if cleanup is otherwise unused.

cleanup:
  if (KERNEL_buf) kfree((void*)KERNEL_buf);

  return result;
}
#endif

int SYSCALL_DMZ_getcwd(char* path_out, size_t size) {
  char* KERNEL_path_out = 0x0;

  const int CHECK_path_out = syscall_verify_buffer(
      path_out, size, 1 /* is_write */, 0 /* allow_null */);
  if (CHECK_path_out < 0) return CHECK_path_out;

  KERNEL_path_out = (char*)kmalloc(size);

  if (!KERNEL_path_out) {
    if (KERNEL_path_out) kfree((void*)KERNEL_path_out);

    return -ENOMEM;
  }

  int result;

  result = vfs_getcwd(KERNEL_path_out, size);

  // TODO(aoates): this should only copy the written bytes, not the full kernel
  // buffer (e.g. in a read() syscall).
  if (path_out) {
    int copy_result = syscall_copy_to_user(KERNEL_path_out, path_out, size);
    if (copy_result) {
      result = copy_result;
      goto cleanup;
    }
  }

  goto cleanup;  // Make the compiler happy if cleanup is otherwise unused.

cleanup:
  if (KERNEL_path_out) kfree((void*)KERNEL_path_out);

  return result;
}

#if ARCH_IS_64_BIT
int SYSCALL_DMZ_stat_32(const char* path, apos_stat_32_t* stat) {
  const char* KERNEL_path = 0x0;
  apos_stat_32_t* KERNEL_stat = 0x0;

  const int SIZE_path = syscall_verify_string(path);
  if (SIZE_path < 0) return SIZE_path;
  const int CHECK_stat = syscall_verify_buffer(
      stat, sizeof(apos_stat_32_t), 1 /* is_write */, 0 /* allow_null */);
  if (CHECK_stat < 0) return CHECK_stat;

  KERNEL_path = (const char*)kmalloc(SIZE_path);
  KERNEL_stat = (apos_stat_32_t*)kmalloc(sizeof(apos_stat_32_t));

  if (!KERNEL_path || !KERNEL_stat) {
    if (KERNEL_path) kfree((void*)KERNEL_path);
    if (KERNEL_stat) kfree((void*)KERNEL_stat);

    return -ENOMEM;
  }

  int result;
  if (path) {
    result = syscall_copy_from_user(path, (void*)KERNEL_path, SIZE_path);
    if (result) goto cleanup;
  }

  result = vfs_stat_32(KERNEL_path, KERNEL_stat);

  // TODO(aoates): this should only copy the written bytes, not the full kernel
  // buffer (e.g. in a read() syscall).
  if (stat) {
    int copy_result =
        syscall_copy_to_user(KERNEL_stat, stat, sizeof(apos_stat_32_t));
    if (copy_result) {
      result = copy_result;
      goto cleanup;
    }
  }

  goto cleanup;  // Make the compiler happy if cleanup is otherwise unused.

cleanup:
  if (KERNEL_path) kfree((void*)KERNEL_path);
  if (KERNEL_stat) kfree((void*)KERNEL_stat);

  return result;
}

#else
int SYSCALL_DMZ_stat(const char* path, apos_stat_t* stat) {
  const char* KERNEL_path = 0x0;
  apos_stat_t* KERNEL_stat = 0x0;

  const int SIZE_path = syscall_verify_string(path);
  if (SIZE_path < 0) return SIZE_path;
  const int CHECK_stat = syscall_verify_buffer(
      stat, sizeof(apos_stat_t), 1 /* is_write */, 0 /* allow_null */);
  if (CHECK_stat < 0) return CHECK_stat;

  KERNEL_path = (const char*)kmalloc(SIZE_path);
  KERNEL_stat = (apos_stat_t*)kmalloc(sizeof(apos_stat_t));

  if (!KERNEL_path || !KERNEL_stat) {
    if (KERNEL_path) kfree((void*)KERNEL_path);
    if (KERNEL_stat) kfree((void*)KERNEL_stat);

    return -ENOMEM;
  }

  int result;
  if (path) {
    result = syscall_copy_from_user(path, (void*)KERNEL_path, SIZE_path);
    if (result) goto cleanup;
  }

  result = vfs_stat(KERNEL_path, KERNEL_stat);

  // TODO(aoates): this should only copy the written bytes, not the full kernel
  // buffer (e.g. in a read() syscall).
  if (stat) {
    int copy_result =
        syscall_copy_to_user(KERNEL_stat, stat, sizeof(apos_stat_t));
    if (copy_result) {
      result = copy_result;
      goto cleanup;
    }
  }

  goto cleanup;  // Make the compiler happy if cleanup is otherwise unused.

cleanup:
  if (KERNEL_path) kfree((void*)KERNEL_path);
  if (KERNEL_stat) kfree((void*)KERNEL_stat);

  return result;
}
#endif

#if ARCH_IS_64_BIT
int SYSCALL_DMZ_lstat_32(const char* path, apos_stat_32_t* stat) {
  const char* KERNEL_path = 0x0;
  apos_stat_32_t* KERNEL_stat = 0x0;

  const int SIZE_path = syscall_verify_string(path);
  if (SIZE_path < 0) return SIZE_path;
  const int CHECK_stat = syscall_verify_buffer(
      stat, sizeof(apos_stat_32_t), 1 /* is_write */, 0 /* allow_null */);
  if (CHECK_stat < 0) return CHECK_stat;

  KERNEL_path = (const char*)kmalloc(SIZE_path);
  KERNEL_stat = (apos_stat_32_t*)kmalloc(sizeof(apos_stat_32_t));

  if (!KERNEL_path || !KERNEL_stat) {
    if (KERNEL_path) kfree((void*)KERNEL_path);
    if (KERNEL_stat) kfree((void*)KERNEL_stat);

    return -ENOMEM;
  }

  int result;
  if (path) {
    result = syscall_copy_from_user(path, (void*)KERNEL_path, SIZE_path);
    if (result) goto cleanup;
  }

  result = vfs_lstat_32(KERNEL_path, KERNEL_stat);

  // TODO(aoates): this should only copy the written bytes, not the full kernel
  // buffer (e.g. in a read() syscall).
  if (stat) {
    int copy_result =
        syscall_copy_to_user(KERNEL_stat, stat, sizeof(apos_stat_32_t));
    if (copy_result) {
      result = copy_result;
      goto cleanup;
    }
  }

  goto cleanup;  // Make the compiler happy if cleanup is otherwise unused.

cleanup:
  if (KERNEL_path) kfree((void*)KERNEL_path);
  if (KERNEL_stat) kfree((void*)KERNEL_stat);

  return result;
}

#else
int SYSCALL_DMZ_lstat(const char* path, apos_stat_t* stat) {
  const char* KERNEL_path = 0x0;
  apos_stat_t* KERNEL_stat = 0x0;

  const int SIZE_path = syscall_verify_string(path);
  if (SIZE_path < 0) return SIZE_path;
  const int CHECK_stat = syscall_verify_buffer(
      stat, sizeof(apos_stat_t), 1 /* is_write */, 0 /* allow_null */);
  if (CHECK_stat < 0) return CHECK_stat;

  KERNEL_path = (const char*)kmalloc(SIZE_path);
  KERNEL_stat = (apos_stat_t*)kmalloc(sizeof(apos_stat_t));

  if (!KERNEL_path || !KERNEL_stat) {
    if (KERNEL_path) kfree((void*)KERNEL_path);
    if (KERNEL_stat) kfree((void*)KERNEL_stat);

    return -ENOMEM;
  }

  int result;
  if (path) {
    result = syscall_copy_from_user(path, (void*)KERNEL_path, SIZE_path);
    if (result) goto cleanup;
  }

  result = vfs_lstat(KERNEL_path, KERNEL_stat);

  // TODO(aoates): this should only copy the written bytes, not the full kernel
  // buffer (e.g. in a read() syscall).
  if (stat) {
    int copy_result =
        syscall_copy_to_user(KERNEL_stat, stat, sizeof(apos_stat_t));
    if (copy_result) {
      result = copy_result;
      goto cleanup;
    }
  }

  goto cleanup;  // Make the compiler happy if cleanup is otherwise unused.

cleanup:
  if (KERNEL_path) kfree((void*)KERNEL_path);
  if (KERNEL_stat) kfree((void*)KERNEL_stat);

  return result;
}
#endif

#if ARCH_IS_64_BIT
int SYSCALL_DMZ_fstat_32(int fd, apos_stat_32_t* stat) {
  apos_stat_32_t* KERNEL_stat = 0x0;

  const int CHECK_stat = syscall_verify_buffer(
      stat, sizeof(apos_stat_32_t), 1 /* is_write */, 0 /* allow_null */);
  if (CHECK_stat < 0) return CHECK_stat;

  KERNEL_stat = (apos_stat_32_t*)kmalloc(sizeof(apos_stat_32_t));

  if (!KERNEL_stat) {
    if (KERNEL_stat) kfree((void*)KERNEL_stat);

    return -ENOMEM;
  }

  int result;

  result = vfs_fstat_32(fd, KERNEL_stat);

  // TODO(aoates): this should only copy the written bytes, not the full kernel
  // buffer (e.g. in a read() syscall).
  if (stat) {
    int copy_result =
        syscall_copy_to_user(KERNEL_stat, stat, sizeof(apos_stat_32_t));
    if (copy_result) {
      result = copy_result;
      goto cleanup;
    }
  }

  goto cleanup;  // Make the compiler happy if cleanup is otherwise unused.

cleanup:
  if (KERNEL_stat) kfree((void*)KERNEL_stat);

  return result;
}

#else
int SYSCALL_DMZ_fstat(int fd, apos_stat_t* stat) {
  apos_stat_t* KERNEL_stat = 0x0;

  const int CHECK_stat = syscall_verify_buffer(
      stat, sizeof(apos_stat_t), 1 /* is_write */, 0 /* allow_null */);
  if (CHECK_stat < 0) return CHECK_stat;

  KERNEL_stat = (apos_stat_t*)kmalloc(sizeof(apos_stat_t));

  if (!KERNEL_stat) {
    if (KERNEL_stat) kfree((void*)KERNEL_stat);

    return -ENOMEM;
  }

  int result;

  result = vfs_fstat(fd, KERNEL_stat);

  // TODO(aoates): this should only copy the written bytes, not the full kernel
  // buffer (e.g. in a read() syscall).
  if (stat) {
    int copy_result =
        syscall_copy_to_user(KERNEL_stat, stat, sizeof(apos_stat_t));
    if (copy_result) {
      result = copy_result;
      goto cleanup;
    }
  }

  goto cleanup;  // Make the compiler happy if cleanup is otherwise unused.

cleanup:
  if (KERNEL_stat) kfree((void*)KERNEL_stat);

  return result;
}
#endif

apos_off_t SYSCALL_DMZ_lseek(int fd, apos_off_t offset, int whence) {
  int result;

  result = vfs_seek(fd, offset, whence);

  // TODO(aoates): this should only copy the written bytes, not the full kernel
  // buffer (e.g. in a read() syscall).

  goto cleanup;  // Make the compiler happy if cleanup is otherwise unused.

cleanup:

  return result;
}

int SYSCALL_DMZ_chdir(const char* path) {
  const char* KERNEL_path = 0x0;

  const int SIZE_path = syscall_verify_string(path);
  if (SIZE_path < 0) return SIZE_path;

  KERNEL_path = (const char*)kmalloc(SIZE_path);

  if (!KERNEL_path) {
    if (KERNEL_path) kfree((void*)KERNEL_path);

    return -ENOMEM;
  }

  int result;
  if (path) {
    result = syscall_copy_from_user(path, (void*)KERNEL_path, SIZE_path);
    if (result) goto cleanup;
  }

  result = vfs_chdir(KERNEL_path);

  // TODO(aoates): this should only copy the written bytes, not the full kernel
  // buffer (e.g. in a read() syscall).

  goto cleanup;  // Make the compiler happy if cleanup is otherwise unused.

cleanup:
  if (KERNEL_path) kfree((void*)KERNEL_path);

  return result;
}

int SYSCALL_DMZ_access(const char* path, int amode) {
  const char* KERNEL_path = 0x0;

  const int SIZE_path = syscall_verify_string(path);
  if (SIZE_path < 0) return SIZE_path;

  KERNEL_path = (const char*)kmalloc(SIZE_path);

  if (!KERNEL_path) {
    if (KERNEL_path) kfree((void*)KERNEL_path);

    return -ENOMEM;
  }

  int result;
  if (path) {
    result = syscall_copy_from_user(path, (void*)KERNEL_path, SIZE_path);
    if (result) goto cleanup;
  }

  result = vfs_access(KERNEL_path, amode);

  // TODO(aoates): this should only copy the written bytes, not the full kernel
  // buffer (e.g. in a read() syscall).

  goto cleanup;  // Make the compiler happy if cleanup is otherwise unused.

cleanup:
  if (KERNEL_path) kfree((void*)KERNEL_path);

  return result;
}

int SYSCALL_DMZ_chown(const char* path, apos_uid_t owner, apos_gid_t group) {
  const char* KERNEL_path = 0x0;

  const int SIZE_path = syscall_verify_string(path);
  if (SIZE_path < 0) return SIZE_path;

  KERNEL_path = (const char*)kmalloc(SIZE_path);

  if (!KERNEL_path) {
    if (KERNEL_path) kfree((void*)KERNEL_path);

    return -ENOMEM;
  }

  int result;
  if (path) {
    result = syscall_copy_from_user(path, (void*)KERNEL_path, SIZE_path);
    if (result) goto cleanup;
  }

  result = vfs_chown(KERNEL_path, owner, group);

  // TODO(aoates): this should only copy the written bytes, not the full kernel
  // buffer (e.g. in a read() syscall).

  goto cleanup;  // Make the compiler happy if cleanup is otherwise unused.

cleanup:
  if (KERNEL_path) kfree((void*)KERNEL_path);

  return result;
}

int SYSCALL_DMZ_fchown(int fd, apos_uid_t owner, apos_gid_t group) {
  int result;

  result = vfs_fchown(fd, owner, group);

  // TODO(aoates): this should only copy the written bytes, not the full kernel
  // buffer (e.g. in a read() syscall).

  goto cleanup;  // Make the compiler happy if cleanup is otherwise unused.

cleanup:

  return result;
}

int SYSCALL_DMZ_lchown(const char* path, apos_uid_t owner, apos_gid_t group) {
  const char* KERNEL_path = 0x0;

  const int SIZE_path = syscall_verify_string(path);
  if (SIZE_path < 0) return SIZE_path;

  KERNEL_path = (const char*)kmalloc(SIZE_path);

  if (!KERNEL_path) {
    if (KERNEL_path) kfree((void*)KERNEL_path);

    return -ENOMEM;
  }

  int result;
  if (path) {
    result = syscall_copy_from_user(path, (void*)KERNEL_path, SIZE_path);
    if (result) goto cleanup;
  }

  result = vfs_lchown(KERNEL_path, owner, group);

  // TODO(aoates): this should only copy the written bytes, not the full kernel
  // buffer (e.g. in a read() syscall).

  goto cleanup;  // Make the compiler happy if cleanup is otherwise unused.

cleanup:
  if (KERNEL_path) kfree((void*)KERNEL_path);

  return result;
}

int SYSCALL_DMZ_chmod(const char* path, apos_mode_t mode) {
  const char* KERNEL_path = 0x0;

  const int SIZE_path = syscall_verify_string(path);
  if (SIZE_path < 0) return SIZE_path;

  KERNEL_path = (const char*)kmalloc(SIZE_path);

  if (!KERNEL_path) {
    if (KERNEL_path) kfree((void*)KERNEL_path);

    return -ENOMEM;
  }

  int result;
  if (path) {
    result = syscall_copy_from_user(path, (void*)KERNEL_path, SIZE_path);
    if (result) goto cleanup;
  }

  result = vfs_chmod(KERNEL_path, mode);

  // TODO(aoates): this should only copy the written bytes, not the full kernel
  // buffer (e.g. in a read() syscall).

  goto cleanup;  // Make the compiler happy if cleanup is otherwise unused.

cleanup:
  if (KERNEL_path) kfree((void*)KERNEL_path);

  return result;
}

int SYSCALL_DMZ_fchmod(int fd, apos_mode_t mode) {
  int result;

  result = vfs_fchmod(fd, mode);

  // TODO(aoates): this should only copy the written bytes, not the full kernel
  // buffer (e.g. in a read() syscall).

  goto cleanup;  // Make the compiler happy if cleanup is otherwise unused.

cleanup:

  return result;
}

apos_pid_t SYSCALL_DMZ_fork(void) {
  int result;

  result = proc_fork_syscall();

  // TODO(aoates): this should only copy the written bytes, not the full kernel
  // buffer (e.g. in a read() syscall).

  goto cleanup;  // Make the compiler happy if cleanup is otherwise unused.

cleanup:

  return result;
}

apos_pid_t SYSCALL_DMZ_vfork(void) {
  int result;

  result = proc_fork_syscall();

  // TODO(aoates): this should only copy the written bytes, not the full kernel
  // buffer (e.g. in a read() syscall).

  goto cleanup;  // Make the compiler happy if cleanup is otherwise unused.

cleanup:

  return result;
}

int SYSCALL_DMZ_exit(int status) {
  int result;

  result = proc_exit_wrapper(status);

  // TODO(aoates): this should only copy the written bytes, not the full kernel
  // buffer (e.g. in a read() syscall).

  goto cleanup;  // Make the compiler happy if cleanup is otherwise unused.

cleanup:

  return result;
}

apos_pid_t SYSCALL_DMZ_wait(int* exit_status) {
  int* KERNEL_exit_status = 0x0;

  const int CHECK_exit_status = syscall_verify_buffer(
      exit_status, sizeof(int), 1 /* is_write */, 1 /* allow_null */);
  if (CHECK_exit_status < 0) return CHECK_exit_status;

  KERNEL_exit_status = !exit_status ? 0x0 : (int*)kmalloc(sizeof(int));

  if ((exit_status && !KERNEL_exit_status)) {
    if (KERNEL_exit_status) kfree((void*)KERNEL_exit_status);

    return -ENOMEM;
  }

  int result;

  result = proc_wait(KERNEL_exit_status);

  // TODO(aoates): this should only copy the written bytes, not the full kernel
  // buffer (e.g. in a read() syscall).
  if (exit_status) {
    int copy_result =
        syscall_copy_to_user(KERNEL_exit_status, exit_status, sizeof(int));
    if (copy_result) {
      result = copy_result;
      goto cleanup;
    }
  }

  goto cleanup;  // Make the compiler happy if cleanup is otherwise unused.

cleanup:
  if (KERNEL_exit_status) kfree((void*)KERNEL_exit_status);

  return result;
}

apos_pid_t SYSCALL_DMZ_waitpid(apos_pid_t child, int* exit_status,
                               int options) {
  int* KERNEL_exit_status = 0x0;

  const int CHECK_exit_status = syscall_verify_buffer(
      exit_status, sizeof(int), 1 /* is_write */, 1 /* allow_null */);
  if (CHECK_exit_status < 0) return CHECK_exit_status;

  KERNEL_exit_status = !exit_status ? 0x0 : (int*)kmalloc(sizeof(int));

  if ((exit_status && !KERNEL_exit_status)) {
    if (KERNEL_exit_status) kfree((void*)KERNEL_exit_status);

    return -ENOMEM;
  }

  int result;

  result = proc_waitpid(child, KERNEL_exit_status, options);

  // TODO(aoates): this should only copy the written bytes, not the full kernel
  // buffer (e.g. in a read() syscall).
  if (exit_status) {
    int copy_result =
        syscall_copy_to_user(KERNEL_exit_status, exit_status, sizeof(int));
    if (copy_result) {
      result = copy_result;
      goto cleanup;
    }
  }

  goto cleanup;  // Make the compiler happy if cleanup is otherwise unused.

cleanup:
  if (KERNEL_exit_status) kfree((void*)KERNEL_exit_status);

  return result;
}

#if ARCH_IS_64_BIT
int SYSCALL_DMZ_execve_32(const char* path, char* const* argv,
                          char* const* envp) {
  int result;

  result = execve_wrapper_32(path, argv, envp);

  // TODO(aoates): this should only copy the written bytes, not the full kernel
  // buffer (e.g. in a read() syscall).

  goto cleanup;  // Make the compiler happy if cleanup is otherwise unused.

cleanup:

  return result;
}

#else
int SYSCALL_DMZ_execve(const char* path, char* const* argv, char* const* envp) {
  int result;

  result = execve_wrapper(path, argv, envp);

  // TODO(aoates): this should only copy the written bytes, not the full kernel
  // buffer (e.g. in a read() syscall).

  goto cleanup;  // Make the compiler happy if cleanup is otherwise unused.

cleanup:

  return result;
}
#endif

apos_pid_t SYSCALL_DMZ_getpid(void) {
  int result;

  result = getpid_wrapper();

  // TODO(aoates): this should only copy the written bytes, not the full kernel
  // buffer (e.g. in a read() syscall).

  goto cleanup;  // Make the compiler happy if cleanup is otherwise unused.

cleanup:

  return result;
}

apos_pid_t SYSCALL_DMZ_getppid(void) {
  int result;

  result = getppid_wrapper();

  // TODO(aoates): this should only copy the written bytes, not the full kernel
  // buffer (e.g. in a read() syscall).

  goto cleanup;  // Make the compiler happy if cleanup is otherwise unused.

cleanup:

  return result;
}

int SYSCALL_DMZ_isatty(int fd) {
  int result;

  result = vfs_isatty(fd);

  // TODO(aoates): this should only copy the written bytes, not the full kernel
  // buffer (e.g. in a read() syscall).

  goto cleanup;  // Make the compiler happy if cleanup is otherwise unused.

cleanup:

  return result;
}

int SYSCALL_DMZ_kill(apos_pid_t pid, int sig) {
  int result;

  result = proc_kill(pid, sig);

  // TODO(aoates): this should only copy the written bytes, not the full kernel
  // buffer (e.g. in a read() syscall).

  goto cleanup;  // Make the compiler happy if cleanup is otherwise unused.

cleanup:

  return result;
}

#if ARCH_IS_64_BIT
int SYSCALL_DMZ_sigaction_32(int signum, const struct ksigaction_32* act,
                             struct ksigaction_32* oldact) {
  const struct ksigaction_32* KERNEL_act = 0x0;
  struct ksigaction_32* KERNEL_oldact = 0x0;

  const int CHECK_act = syscall_verify_buffer(
      act, sizeof(struct ksigaction_32), 0 /* is_write */, 1 /* allow_null */);
  if (CHECK_act < 0) return CHECK_act;
  const int CHECK_oldact =
      syscall_verify_buffer(oldact, sizeof(struct ksigaction_32),
                            1 /* is_write */, 1 /* allow_null */);
  if (CHECK_oldact < 0) return CHECK_oldact;

  KERNEL_act =
      !act ? 0x0
           : (const struct ksigaction_32*)kmalloc(sizeof(struct ksigaction_32));
  KERNEL_oldact =
      !oldact ? 0x0
              : (struct ksigaction_32*)kmalloc(sizeof(struct ksigaction_32));

  if ((act && !KERNEL_act) || (oldact && !KERNEL_oldact)) {
    if (KERNEL_act) kfree((void*)KERNEL_act);
    if (KERNEL_oldact) kfree((void*)KERNEL_oldact);

    return -ENOMEM;
  }

  int result;
  if (act) {
    result = syscall_copy_from_user(act, (void*)KERNEL_act,
                                    sizeof(struct ksigaction_32));
    if (result) goto cleanup;
  }

  result = proc_sigaction_32(signum, KERNEL_act, KERNEL_oldact);

  // TODO(aoates): this should only copy the written bytes, not the full kernel
  // buffer (e.g. in a read() syscall).
  if (oldact) {
    int copy_result = syscall_copy_to_user(KERNEL_oldact, oldact,
                                           sizeof(struct ksigaction_32));
    if (copy_result) {
      result = copy_result;
      goto cleanup;
    }
  }

  goto cleanup;  // Make the compiler happy if cleanup is otherwise unused.

cleanup:
  if (KERNEL_act) kfree((void*)KERNEL_act);
  if (KERNEL_oldact) kfree((void*)KERNEL_oldact);

  return result;
}

#else
int SYSCALL_DMZ_sigaction(int signum, const struct ksigaction* act,
                          struct ksigaction* oldact) {
  const struct ksigaction* KERNEL_act = 0x0;
  struct ksigaction* KERNEL_oldact = 0x0;

  const int CHECK_act = syscall_verify_buffer(
      act, sizeof(struct ksigaction), 0 /* is_write */, 1 /* allow_null */);
  if (CHECK_act < 0) return CHECK_act;
  const int CHECK_oldact = syscall_verify_buffer(
      oldact, sizeof(struct ksigaction), 1 /* is_write */, 1 /* allow_null */);
  if (CHECK_oldact < 0) return CHECK_oldact;

  KERNEL_act =
      !act ? 0x0 : (const struct ksigaction*)kmalloc(sizeof(struct ksigaction));
  KERNEL_oldact =
      !oldact ? 0x0 : (struct ksigaction*)kmalloc(sizeof(struct ksigaction));

  if ((act && !KERNEL_act) || (oldact && !KERNEL_oldact)) {
    if (KERNEL_act) kfree((void*)KERNEL_act);
    if (KERNEL_oldact) kfree((void*)KERNEL_oldact);

    return -ENOMEM;
  }

  int result;
  if (act) {
    result = syscall_copy_from_user(act, (void*)KERNEL_act,
                                    sizeof(struct ksigaction));
    if (result) goto cleanup;
  }

  result = proc_sigaction(signum, KERNEL_act, KERNEL_oldact);

  // TODO(aoates): this should only copy the written bytes, not the full kernel
  // buffer (e.g. in a read() syscall).
  if (oldact) {
    int copy_result =
        syscall_copy_to_user(KERNEL_oldact, oldact, sizeof(struct ksigaction));
    if (copy_result) {
      result = copy_result;
      goto cleanup;
    }
  }

  goto cleanup;  // Make the compiler happy if cleanup is otherwise unused.

cleanup:
  if (KERNEL_act) kfree((void*)KERNEL_act);
  if (KERNEL_oldact) kfree((void*)KERNEL_oldact);

  return result;
}
#endif

int SYSCALL_DMZ_sigprocmask(int how, const ksigset_t* set, ksigset_t* oset) {
  const ksigset_t* KERNEL_set = 0x0;
  ksigset_t* KERNEL_oset = 0x0;

  const int CHECK_set = syscall_verify_buffer(
      set, sizeof(ksigset_t), 0 /* is_write */, 1 /* allow_null */);
  if (CHECK_set < 0) return CHECK_set;
  const int CHECK_oset = syscall_verify_buffer(
      oset, sizeof(ksigset_t), 1 /* is_write */, 1 /* allow_null */);
  if (CHECK_oset < 0) return CHECK_oset;

  KERNEL_set = !set ? 0x0 : (const ksigset_t*)kmalloc(sizeof(ksigset_t));
  KERNEL_oset = !oset ? 0x0 : (ksigset_t*)kmalloc(sizeof(ksigset_t));

  if ((set && !KERNEL_set) || (oset && !KERNEL_oset)) {
    if (KERNEL_set) kfree((void*)KERNEL_set);
    if (KERNEL_oset) kfree((void*)KERNEL_oset);

    return -ENOMEM;
  }

  int result;
  if (set) {
    result = syscall_copy_from_user(set, (void*)KERNEL_set, sizeof(ksigset_t));
    if (result) goto cleanup;
  }

  result = proc_sigprocmask(how, KERNEL_set, KERNEL_oset);

  // TODO(aoates): this should only copy the written bytes, not the full kernel
  // buffer (e.g. in a read() syscall).
  if (oset) {
    int copy_result =
        syscall_copy_to_user(KERNEL_oset, oset, sizeof(ksigset_t));
    if (copy_result) {
      result = copy_result;
      goto cleanup;
    }
  }

  goto cleanup;  // Make the compiler happy if cleanup is otherwise unused.

cleanup:
  if (KERNEL_set) kfree((void*)KERNEL_set);
  if (KERNEL_oset) kfree((void*)KERNEL_oset);

  return result;
}

int SYSCALL_DMZ_sigpending(ksigset_t* oset) {
  ksigset_t* KERNEL_oset = 0x0;

  const int CHECK_oset = syscall_verify_buffer(
      oset, sizeof(ksigset_t), 1 /* is_write */, 0 /* allow_null */);
  if (CHECK_oset < 0) return CHECK_oset;

  KERNEL_oset = (ksigset_t*)kmalloc(sizeof(ksigset_t));

  if (!KERNEL_oset) {
    if (KERNEL_oset) kfree((void*)KERNEL_oset);

    return -ENOMEM;
  }

  int result;

  result = proc_sigpending(KERNEL_oset);

  // TODO(aoates): this should only copy the written bytes, not the full kernel
  // buffer (e.g. in a read() syscall).
  if (oset) {
    int copy_result =
        syscall_copy_to_user(KERNEL_oset, oset, sizeof(ksigset_t));
    if (copy_result) {
      result = copy_result;
      goto cleanup;
    }
  }

  goto cleanup;  // Make the compiler happy if cleanup is otherwise unused.

cleanup:
  if (KERNEL_oset) kfree((void*)KERNEL_oset);

  return result;
}

int SYSCALL_DMZ_sigsuspend(const ksigset_t* sigmask) {
  const ksigset_t* KERNEL_sigmask = 0x0;

  const int CHECK_sigmask = syscall_verify_buffer(
      sigmask, sizeof(ksigset_t), 0 /* is_write */, 0 /* allow_null */);
  if (CHECK_sigmask < 0) return CHECK_sigmask;

  KERNEL_sigmask = (const ksigset_t*)kmalloc(sizeof(ksigset_t));

  if (!KERNEL_sigmask) {
    if (KERNEL_sigmask) kfree((void*)KERNEL_sigmask);

    return -ENOMEM;
  }

  int result;
  if (sigmask) {
    result = syscall_copy_from_user(sigmask, (void*)KERNEL_sigmask,
                                    sizeof(ksigset_t));
    if (result) goto cleanup;
  }

  result = proc_sigsuspend(KERNEL_sigmask);

  // TODO(aoates): this should only copy the written bytes, not the full kernel
  // buffer (e.g. in a read() syscall).

  goto cleanup;  // Make the compiler happy if cleanup is otherwise unused.

cleanup:
  if (KERNEL_sigmask) kfree((void*)KERNEL_sigmask);

  return result;
}

int SYSCALL_DMZ_sigreturn(const ksigset_t* old_mask,
                          const user_context_t* context,
                          const syscall_context_t* syscall_context) {
  const ksigset_t* KERNEL_old_mask = 0x0;
  const user_context_t* KERNEL_context = 0x0;
  const syscall_context_t* KERNEL_syscall_context = 0x0;

  const int CHECK_old_mask = syscall_verify_buffer(
      old_mask, sizeof(ksigset_t), 0 /* is_write */, 0 /* allow_null */);
  if (CHECK_old_mask < 0) return CHECK_old_mask;
  const int CHECK_context = syscall_verify_buffer(
      context, sizeof(user_context_t), 0 /* is_write */, 0 /* allow_null */);
  if (CHECK_context < 0) return CHECK_context;
  const int CHECK_syscall_context =
      syscall_verify_buffer(syscall_context, sizeof(syscall_context_t),
                            0 /* is_write */, 1 /* allow_null */);
  if (CHECK_syscall_context < 0) return CHECK_syscall_context;

  KERNEL_old_mask = (const ksigset_t*)kmalloc(sizeof(ksigset_t));
  KERNEL_context = (const user_context_t*)kmalloc(sizeof(user_context_t));
  KERNEL_syscall_context =
      !syscall_context
          ? 0x0
          : (const syscall_context_t*)kmalloc(sizeof(syscall_context_t));

  if (!KERNEL_old_mask || !KERNEL_context ||
      (syscall_context && !KERNEL_syscall_context)) {
    if (KERNEL_old_mask) kfree((void*)KERNEL_old_mask);
    if (KERNEL_context) kfree((void*)KERNEL_context);
    if (KERNEL_syscall_context) kfree((void*)KERNEL_syscall_context);

    return -ENOMEM;
  }

  int result;
  if (old_mask) {
    result = syscall_copy_from_user(old_mask, (void*)KERNEL_old_mask,
                                    sizeof(ksigset_t));
    if (result) goto cleanup;
  }
  if (context) {
    result = syscall_copy_from_user(context, (void*)KERNEL_context,
                                    sizeof(user_context_t));
    if (result) goto cleanup;
  }
  if (syscall_context) {
    result =
        syscall_copy_from_user(syscall_context, (void*)KERNEL_syscall_context,
                               sizeof(syscall_context_t));
    if (result) goto cleanup;
  }

  result =
      proc_sigreturn(KERNEL_old_mask, KERNEL_context, KERNEL_syscall_context);

  // TODO(aoates): this should only copy the written bytes, not the full kernel
  // buffer (e.g. in a read() syscall).

  goto cleanup;  // Make the compiler happy if cleanup is otherwise unused.

cleanup:
  if (KERNEL_old_mask) kfree((void*)KERNEL_old_mask);
  if (KERNEL_context) kfree((void*)KERNEL_context);
  if (KERNEL_syscall_context) kfree((void*)KERNEL_syscall_context);

  return result;
}

unsigned int SYSCALL_DMZ_alarm_ms(unsigned int seconds) {
  int result;

  result = proc_alarm_ms(seconds);

  // TODO(aoates): this should only copy the written bytes, not the full kernel
  // buffer (e.g. in a read() syscall).

  goto cleanup;  // Make the compiler happy if cleanup is otherwise unused.

cleanup:

  return result;
}

int SYSCALL_DMZ_setuid(apos_uid_t uid) {
  int result;

  result = setuid(uid);

  // TODO(aoates): this should only copy the written bytes, not the full kernel
  // buffer (e.g. in a read() syscall).

  goto cleanup;  // Make the compiler happy if cleanup is otherwise unused.

cleanup:

  return result;
}

int SYSCALL_DMZ_setgid(apos_gid_t gid) {
  int result;

  result = setgid(gid);

  // TODO(aoates): this should only copy the written bytes, not the full kernel
  // buffer (e.g. in a read() syscall).

  goto cleanup;  // Make the compiler happy if cleanup is otherwise unused.

cleanup:

  return result;
}

apos_uid_t SYSCALL_DMZ_getuid(void) {
  int result;

  result = getuid();

  // TODO(aoates): this should only copy the written bytes, not the full kernel
  // buffer (e.g. in a read() syscall).

  goto cleanup;  // Make the compiler happy if cleanup is otherwise unused.

cleanup:

  return result;
}

apos_gid_t SYSCALL_DMZ_getgid(void) {
  int result;

  result = getgid();

  // TODO(aoates): this should only copy the written bytes, not the full kernel
  // buffer (e.g. in a read() syscall).

  goto cleanup;  // Make the compiler happy if cleanup is otherwise unused.

cleanup:

  return result;
}

int SYSCALL_DMZ_seteuid(apos_uid_t uid) {
  int result;

  result = seteuid(uid);

  // TODO(aoates): this should only copy the written bytes, not the full kernel
  // buffer (e.g. in a read() syscall).

  goto cleanup;  // Make the compiler happy if cleanup is otherwise unused.

cleanup:

  return result;
}

int SYSCALL_DMZ_setegid(apos_gid_t gid) {
  int result;

  result = setegid(gid);

  // TODO(aoates): this should only copy the written bytes, not the full kernel
  // buffer (e.g. in a read() syscall).

  goto cleanup;  // Make the compiler happy if cleanup is otherwise unused.

cleanup:

  return result;
}

apos_uid_t SYSCALL_DMZ_geteuid(void) {
  int result;

  result = geteuid();

  // TODO(aoates): this should only copy the written bytes, not the full kernel
  // buffer (e.g. in a read() syscall).

  goto cleanup;  // Make the compiler happy if cleanup is otherwise unused.

cleanup:

  return result;
}

apos_gid_t SYSCALL_DMZ_getegid(void) {
  int result;

  result = getegid();

  // TODO(aoates): this should only copy the written bytes, not the full kernel
  // buffer (e.g. in a read() syscall).

  goto cleanup;  // Make the compiler happy if cleanup is otherwise unused.

cleanup:

  return result;
}

int SYSCALL_DMZ_setreuid(apos_uid_t ruid, apos_uid_t euid) {
  int result;

  result = setreuid(ruid, euid);

  // TODO(aoates): this should only copy the written bytes, not the full kernel
  // buffer (e.g. in a read() syscall).

  goto cleanup;  // Make the compiler happy if cleanup is otherwise unused.

cleanup:

  return result;
}

int SYSCALL_DMZ_setregid(apos_gid_t rgid, apos_gid_t egid) {
  int result;

  result = setregid(rgid, egid);

  // TODO(aoates): this should only copy the written bytes, not the full kernel
  // buffer (e.g. in a read() syscall).

  goto cleanup;  // Make the compiler happy if cleanup is otherwise unused.

cleanup:

  return result;
}

apos_pid_t SYSCALL_DMZ_getpgid(apos_pid_t pid) {
  int result;

  result = getpgid(pid);

  // TODO(aoates): this should only copy the written bytes, not the full kernel
  // buffer (e.g. in a read() syscall).

  goto cleanup;  // Make the compiler happy if cleanup is otherwise unused.

cleanup:

  return result;
}

int SYSCALL_DMZ_setpgid(apos_pid_t pid, apos_pid_t pgid) {
  int result;

  result = setpgid(pid, pgid);

  // TODO(aoates): this should only copy the written bytes, not the full kernel
  // buffer (e.g. in a read() syscall).

  goto cleanup;  // Make the compiler happy if cleanup is otherwise unused.

cleanup:

  return result;
}

#if ARCH_IS_64_BIT
int SYSCALL_DMZ_mmap_32(void* addr_inout, size_t length, int prot, int flags,
                        int fd, apos_off_t offset) {
  void* KERNEL_addr_inout = 0x0;

  const int CHECK_addr_inout = syscall_verify_buffer(
      addr_inout, sizeof(void*), 1 /* is_write */, 0 /* allow_null */);
  if (CHECK_addr_inout < 0) return CHECK_addr_inout;

  KERNEL_addr_inout = (void*)kmalloc(sizeof(void*));

  if (!KERNEL_addr_inout) {
    if (KERNEL_addr_inout) kfree((void*)KERNEL_addr_inout);

    return -ENOMEM;
  }

  int result;
  if (addr_inout) {
    result = syscall_copy_from_user(addr_inout, (void*)KERNEL_addr_inout,
                                    sizeof(void*));
    if (result) goto cleanup;
  }

  result = mmap_wrapper_32(KERNEL_addr_inout, length, prot, flags, fd, offset);

  // TODO(aoates): this should only copy the written bytes, not the full kernel
  // buffer (e.g. in a read() syscall).
  if (addr_inout) {
    int copy_result =
        syscall_copy_to_user(KERNEL_addr_inout, addr_inout, sizeof(void*));
    if (copy_result) {
      result = copy_result;
      goto cleanup;
    }
  }

  goto cleanup;  // Make the compiler happy if cleanup is otherwise unused.

cleanup:
  if (KERNEL_addr_inout) kfree((void*)KERNEL_addr_inout);

  return result;
}

#else
int SYSCALL_DMZ_mmap(void* addr_inout, size_t length, int prot, int flags,
                     int fd, apos_off_t offset) {
  void* KERNEL_addr_inout = 0x0;

  const int CHECK_addr_inout = syscall_verify_buffer(
      addr_inout, sizeof(void*), 1 /* is_write */, 0 /* allow_null */);
  if (CHECK_addr_inout < 0) return CHECK_addr_inout;

  KERNEL_addr_inout = (void*)kmalloc(sizeof(void*));

  if (!KERNEL_addr_inout) {
    if (KERNEL_addr_inout) kfree((void*)KERNEL_addr_inout);

    return -ENOMEM;
  }

  int result;
  if (addr_inout) {
    result = syscall_copy_from_user(addr_inout, (void*)KERNEL_addr_inout,
                                    sizeof(void*));
    if (result) goto cleanup;
  }

  result = mmap_wrapper(KERNEL_addr_inout, length, prot, flags, fd, offset);

  // TODO(aoates): this should only copy the written bytes, not the full kernel
  // buffer (e.g. in a read() syscall).
  if (addr_inout) {
    int copy_result =
        syscall_copy_to_user(KERNEL_addr_inout, addr_inout, sizeof(void*));
    if (copy_result) {
      result = copy_result;
      goto cleanup;
    }
  }

  goto cleanup;  // Make the compiler happy if cleanup is otherwise unused.

cleanup:
  if (KERNEL_addr_inout) kfree((void*)KERNEL_addr_inout);

  return result;
}
#endif

int SYSCALL_DMZ_munmap(void* addr, size_t length) {
  int result;

  result = do_munmap(addr, length);

  // TODO(aoates): this should only copy the written bytes, not the full kernel
  // buffer (e.g. in a read() syscall).

  goto cleanup;  // Make the compiler happy if cleanup is otherwise unused.

cleanup:

  return result;
}

int SYSCALL_DMZ_symlink(const char* path1, const char* path2) {
  const char* KERNEL_path1 = 0x0;
  const char* KERNEL_path2 = 0x0;

  const int SIZE_path1 = syscall_verify_string(path1);
  if (SIZE_path1 < 0) return SIZE_path1;
  const int SIZE_path2 = syscall_verify_string(path2);
  if (SIZE_path2 < 0) return SIZE_path2;

  KERNEL_path1 = (const char*)kmalloc(SIZE_path1);
  KERNEL_path2 = (const char*)kmalloc(SIZE_path2);

  if (!KERNEL_path1 || !KERNEL_path2) {
    if (KERNEL_path1) kfree((void*)KERNEL_path1);
    if (KERNEL_path2) kfree((void*)KERNEL_path2);

    return -ENOMEM;
  }

  int result;
  if (path1) {
    result = syscall_copy_from_user(path1, (void*)KERNEL_path1, SIZE_path1);
    if (result) goto cleanup;
  }
  if (path2) {
    result = syscall_copy_from_user(path2, (void*)KERNEL_path2, SIZE_path2);
    if (result) goto cleanup;
  }

  result = vfs_symlink(KERNEL_path1, KERNEL_path2);

  // TODO(aoates): this should only copy the written bytes, not the full kernel
  // buffer (e.g. in a read() syscall).

  goto cleanup;  // Make the compiler happy if cleanup is otherwise unused.

cleanup:
  if (KERNEL_path1) kfree((void*)KERNEL_path1);
  if (KERNEL_path2) kfree((void*)KERNEL_path2);

  return result;
}

int SYSCALL_DMZ_readlink(const char* path, char* buf, size_t bufsize) {
  const char* KERNEL_path = 0x0;
  char* KERNEL_buf = 0x0;

  const int SIZE_path = syscall_verify_string(path);
  if (SIZE_path < 0) return SIZE_path;
  const int CHECK_buf =
      syscall_verify_buffer(buf, bufsize, 1 /* is_write */, 0 /* allow_null */);
  if (CHECK_buf < 0) return CHECK_buf;

  KERNEL_path = (const char*)kmalloc(SIZE_path);
  KERNEL_buf = (char*)kmalloc(bufsize);

  if (!KERNEL_path || !KERNEL_buf) {
    if (KERNEL_path) kfree((void*)KERNEL_path);
    if (KERNEL_buf) kfree((void*)KERNEL_buf);

    return -ENOMEM;
  }

  int result;
  if (path) {
    result = syscall_copy_from_user(path, (void*)KERNEL_path, SIZE_path);
    if (result) goto cleanup;
  }

  result = vfs_readlink(KERNEL_path, KERNEL_buf, bufsize);

  // TODO(aoates): this should only copy the written bytes, not the full kernel
  // buffer (e.g. in a read() syscall).
  if (buf) {
    int copy_result = syscall_copy_to_user(KERNEL_buf, buf, bufsize);
    if (copy_result) {
      result = copy_result;
      goto cleanup;
    }
  }

  goto cleanup;  // Make the compiler happy if cleanup is otherwise unused.

cleanup:
  if (KERNEL_path) kfree((void*)KERNEL_path);
  if (KERNEL_buf) kfree((void*)KERNEL_buf);

  return result;
}

int SYSCALL_DMZ_sleep_ms(unsigned int seconds) {
  int result;

  result = ksleep(seconds);

  // TODO(aoates): this should only copy the written bytes, not the full kernel
  // buffer (e.g. in a read() syscall).

  goto cleanup;  // Make the compiler happy if cleanup is otherwise unused.

cleanup:

  return result;
}

int SYSCALL_DMZ_apos_get_time(struct apos_tm* t) {
  struct apos_tm* KERNEL_t = 0x0;

  const int CHECK_t = syscall_verify_buffer(
      t, sizeof(struct apos_tm), 1 /* is_write */, 0 /* allow_null */);
  if (CHECK_t < 0) return CHECK_t;

  KERNEL_t = (struct apos_tm*)kmalloc(sizeof(struct apos_tm));

  if (!KERNEL_t) {
    if (KERNEL_t) kfree((void*)KERNEL_t);

    return -ENOMEM;
  }

  int result;

  result = apos_get_time(KERNEL_t);

  // TODO(aoates): this should only copy the written bytes, not the full kernel
  // buffer (e.g. in a read() syscall).
  if (t) {
    int copy_result = syscall_copy_to_user(KERNEL_t, t, sizeof(struct apos_tm));
    if (copy_result) {
      result = copy_result;
      goto cleanup;
    }
  }

  goto cleanup;  // Make the compiler happy if cleanup is otherwise unused.

cleanup:
  if (KERNEL_t) kfree((void*)KERNEL_t);

  return result;
}

int SYSCALL_DMZ_pipe(int* fildes) {
  int* KERNEL_fildes = 0x0;

  const int CHECK_fildes = syscall_verify_buffer(
      fildes, sizeof(int[2]), 1 /* is_write */, 0 /* allow_null */);
  if (CHECK_fildes < 0) return CHECK_fildes;

  KERNEL_fildes = (int*)kmalloc(sizeof(int[2]));

  if (!KERNEL_fildes) {
    if (KERNEL_fildes) kfree((void*)KERNEL_fildes);

    return -ENOMEM;
  }

  int result;

  result = vfs_pipe(KERNEL_fildes);

  // TODO(aoates): this should only copy the written bytes, not the full kernel
  // buffer (e.g. in a read() syscall).
  if (fildes) {
    int copy_result =
        syscall_copy_to_user(KERNEL_fildes, fildes, sizeof(int[2]));
    if (copy_result) {
      result = copy_result;
      goto cleanup;
    }
  }

  goto cleanup;  // Make the compiler happy if cleanup is otherwise unused.

cleanup:
  if (KERNEL_fildes) kfree((void*)KERNEL_fildes);

  return result;
}

apos_mode_t SYSCALL_DMZ_umask(apos_mode_t cmask) {
  int result;

  result = proc_umask(cmask);

  // TODO(aoates): this should only copy the written bytes, not the full kernel
  // buffer (e.g. in a read() syscall).

  goto cleanup;  // Make the compiler happy if cleanup is otherwise unused.

cleanup:

  return result;
}

apos_pid_t SYSCALL_DMZ_setsid(void) {
  int result;

  result = proc_setsid();

  // TODO(aoates): this should only copy the written bytes, not the full kernel
  // buffer (e.g. in a read() syscall).

  goto cleanup;  // Make the compiler happy if cleanup is otherwise unused.

cleanup:

  return result;
}

apos_pid_t SYSCALL_DMZ_getsid(apos_pid_t pid) {
  int result;

  result = proc_getsid(pid);

  // TODO(aoates): this should only copy the written bytes, not the full kernel
  // buffer (e.g. in a read() syscall).

  goto cleanup;  // Make the compiler happy if cleanup is otherwise unused.

cleanup:

  return result;
}

apos_pid_t SYSCALL_DMZ_tcgetpgrp(int fd) {
  int result;

  result = proc_tcgetpgrp(fd);

  // TODO(aoates): this should only copy the written bytes, not the full kernel
  // buffer (e.g. in a read() syscall).

  goto cleanup;  // Make the compiler happy if cleanup is otherwise unused.

cleanup:

  return result;
}

int SYSCALL_DMZ_tcsetpgrp(int fd, apos_pid_t pgid) {
  int result;

  result = proc_tcsetpgrp(fd, pgid);

  // TODO(aoates): this should only copy the written bytes, not the full kernel
  // buffer (e.g. in a read() syscall).

  goto cleanup;  // Make the compiler happy if cleanup is otherwise unused.

cleanup:

  return result;
}

apos_pid_t SYSCALL_DMZ_tcgetsid(int fd) {
  int result;

  result = proc_tcgetsid(fd);

  // TODO(aoates): this should only copy the written bytes, not the full kernel
  // buffer (e.g. in a read() syscall).

  goto cleanup;  // Make the compiler happy if cleanup is otherwise unused.

cleanup:

  return result;
}

int SYSCALL_DMZ_tcdrain(int fd) {
  int result;

  result = tty_tcdrain(fd);

  // TODO(aoates): this should only copy the written bytes, not the full kernel
  // buffer (e.g. in a read() syscall).

  goto cleanup;  // Make the compiler happy if cleanup is otherwise unused.

cleanup:

  return result;
}

int SYSCALL_DMZ_tcflush(int fd, int action) {
  int result;

  result = tty_tcflush(fd, action);

  // TODO(aoates): this should only copy the written bytes, not the full kernel
  // buffer (e.g. in a read() syscall).

  goto cleanup;  // Make the compiler happy if cleanup is otherwise unused.

cleanup:

  return result;
}

int SYSCALL_DMZ_tcgetattr(int fd, struct ktermios* t) {
  struct ktermios* KERNEL_t = 0x0;

  const int CHECK_t = syscall_verify_buffer(
      t, sizeof(struct ktermios), 1 /* is_write */, 0 /* allow_null */);
  if (CHECK_t < 0) return CHECK_t;

  KERNEL_t = (struct ktermios*)kmalloc(sizeof(struct ktermios));

  if (!KERNEL_t) {
    if (KERNEL_t) kfree((void*)KERNEL_t);

    return -ENOMEM;
  }

  int result;

  result = tty_tcgetattr(fd, KERNEL_t);

  // TODO(aoates): this should only copy the written bytes, not the full kernel
  // buffer (e.g. in a read() syscall).
  if (t) {
    int copy_result =
        syscall_copy_to_user(KERNEL_t, t, sizeof(struct ktermios));
    if (copy_result) {
      result = copy_result;
      goto cleanup;
    }
  }

  goto cleanup;  // Make the compiler happy if cleanup is otherwise unused.

cleanup:
  if (KERNEL_t) kfree((void*)KERNEL_t);

  return result;
}

int SYSCALL_DMZ_tcsetattr(int fd, int optional_actions,
                          const struct ktermios* t) {
  const struct ktermios* KERNEL_t = 0x0;

  const int CHECK_t = syscall_verify_buffer(
      t, sizeof(struct ktermios), 0 /* is_write */, 0 /* allow_null */);
  if (CHECK_t < 0) return CHECK_t;

  KERNEL_t = (const struct ktermios*)kmalloc(sizeof(struct ktermios));

  if (!KERNEL_t) {
    if (KERNEL_t) kfree((void*)KERNEL_t);

    return -ENOMEM;
  }

  int result;
  if (t) {
    result =
        syscall_copy_from_user(t, (void*)KERNEL_t, sizeof(struct ktermios));
    if (result) goto cleanup;
  }

  result = tty_tcsetattr(fd, optional_actions, KERNEL_t);

  // TODO(aoates): this should only copy the written bytes, not the full kernel
  // buffer (e.g. in a read() syscall).

  goto cleanup;  // Make the compiler happy if cleanup is otherwise unused.

cleanup:
  if (KERNEL_t) kfree((void*)KERNEL_t);

  return result;
}

int SYSCALL_DMZ_ftruncate(int fd, apos_off_t length) {
  int result;

  result = vfs_ftruncate(fd, length);

  // TODO(aoates): this should only copy the written bytes, not the full kernel
  // buffer (e.g. in a read() syscall).

  goto cleanup;  // Make the compiler happy if cleanup is otherwise unused.

cleanup:

  return result;
}

int SYSCALL_DMZ_truncate(const char* path, apos_off_t length) {
  const char* KERNEL_path = 0x0;

  const int SIZE_path = syscall_verify_string(path);
  if (SIZE_path < 0) return SIZE_path;

  KERNEL_path = (const char*)kmalloc(SIZE_path);

  if (!KERNEL_path) {
    if (KERNEL_path) kfree((void*)KERNEL_path);

    return -ENOMEM;
  }

  int result;
  if (path) {
    result = syscall_copy_from_user(path, (void*)KERNEL_path, SIZE_path);
    if (result) goto cleanup;
  }

  result = vfs_truncate(KERNEL_path, length);

  // TODO(aoates): this should only copy the written bytes, not the full kernel
  // buffer (e.g. in a read() syscall).

  goto cleanup;  // Make the compiler happy if cleanup is otherwise unused.

cleanup:
  if (KERNEL_path) kfree((void*)KERNEL_path);

  return result;
}

int SYSCALL_DMZ_poll(struct apos_pollfd* fds, apos_nfds_t nfds, int timeout) {
  struct apos_pollfd* KERNEL_fds = 0x0;

  const int CHECK_fds =
      syscall_verify_buffer(fds, sizeof(struct apos_pollfd) * nfds,
                            1 /* is_write */, 0 /* allow_null */);
  if (CHECK_fds < 0) return CHECK_fds;

  KERNEL_fds = (struct apos_pollfd*)kmalloc(sizeof(struct apos_pollfd) * nfds);

  if (!KERNEL_fds) {
    if (KERNEL_fds) kfree((void*)KERNEL_fds);

    return -ENOMEM;
  }

  int result;
  if (fds) {
    result = syscall_copy_from_user(fds, (void*)KERNEL_fds,
                                    sizeof(struct apos_pollfd) * nfds);
    if (result) goto cleanup;
  }

  result = vfs_poll(KERNEL_fds, nfds, timeout);

  // TODO(aoates): this should only copy the written bytes, not the full kernel
  // buffer (e.g. in a read() syscall).
  if (fds) {
    int copy_result = syscall_copy_to_user(KERNEL_fds, fds,
                                           sizeof(struct apos_pollfd) * nfds);
    if (copy_result) {
      result = copy_result;
      goto cleanup;
    }
  }

  goto cleanup;  // Make the compiler happy if cleanup is otherwise unused.

cleanup:
  if (KERNEL_fds) kfree((void*)KERNEL_fds);

  return result;
}

#if ARCH_IS_64_BIT
int SYSCALL_DMZ_getrlimit_32(int resource, struct apos_rlimit_32* lim) {
  struct apos_rlimit_32* KERNEL_lim = 0x0;

  const int CHECK_lim = syscall_verify_buffer(
      lim, sizeof(struct apos_rlimit), 1 /* is_write */, 0 /* allow_null */);
  if (CHECK_lim < 0) return CHECK_lim;

  KERNEL_lim = (struct apos_rlimit_32*)kmalloc(sizeof(struct apos_rlimit));

  if (!KERNEL_lim) {
    if (KERNEL_lim) kfree((void*)KERNEL_lim);

    return -ENOMEM;
  }

  int result;

  result = proc_getrlimit_32(resource, KERNEL_lim);

  // TODO(aoates): this should only copy the written bytes, not the full kernel
  // buffer (e.g. in a read() syscall).
  if (lim) {
    int copy_result =
        syscall_copy_to_user(KERNEL_lim, lim, sizeof(struct apos_rlimit));
    if (copy_result) {
      result = copy_result;
      goto cleanup;
    }
  }

  goto cleanup;  // Make the compiler happy if cleanup is otherwise unused.

cleanup:
  if (KERNEL_lim) kfree((void*)KERNEL_lim);

  return result;
}

#else
int SYSCALL_DMZ_getrlimit(int resource, struct apos_rlimit* lim) {
  struct apos_rlimit* KERNEL_lim = 0x0;

  const int CHECK_lim = syscall_verify_buffer(
      lim, sizeof(struct apos_rlimit), 1 /* is_write */, 0 /* allow_null */);
  if (CHECK_lim < 0) return CHECK_lim;

  KERNEL_lim = (struct apos_rlimit*)kmalloc(sizeof(struct apos_rlimit));

  if (!KERNEL_lim) {
    if (KERNEL_lim) kfree((void*)KERNEL_lim);

    return -ENOMEM;
  }

  int result;

  result = proc_getrlimit(resource, KERNEL_lim);

  // TODO(aoates): this should only copy the written bytes, not the full kernel
  // buffer (e.g. in a read() syscall).
  if (lim) {
    int copy_result =
        syscall_copy_to_user(KERNEL_lim, lim, sizeof(struct apos_rlimit));
    if (copy_result) {
      result = copy_result;
      goto cleanup;
    }
  }

  goto cleanup;  // Make the compiler happy if cleanup is otherwise unused.

cleanup:
  if (KERNEL_lim) kfree((void*)KERNEL_lim);

  return result;
}
#endif

#if ARCH_IS_64_BIT
int SYSCALL_DMZ_setrlimit_32(int resource, const struct apos_rlimit_32* lim) {
  const struct apos_rlimit_32* KERNEL_lim = 0x0;

  const int CHECK_lim = syscall_verify_buffer(
      lim, sizeof(struct apos_rlimit), 0 /* is_write */, 0 /* allow_null */);
  if (CHECK_lim < 0) return CHECK_lim;

  KERNEL_lim =
      (const struct apos_rlimit_32*)kmalloc(sizeof(struct apos_rlimit));

  if (!KERNEL_lim) {
    if (KERNEL_lim) kfree((void*)KERNEL_lim);

    return -ENOMEM;
  }

  int result;
  if (lim) {
    result = syscall_copy_from_user(lim, (void*)KERNEL_lim,
                                    sizeof(struct apos_rlimit));
    if (result) goto cleanup;
  }

  result = proc_setrlimit_32(resource, KERNEL_lim);

  // TODO(aoates): this should only copy the written bytes, not the full kernel
  // buffer (e.g. in a read() syscall).

  goto cleanup;  // Make the compiler happy if cleanup is otherwise unused.

cleanup:
  if (KERNEL_lim) kfree((void*)KERNEL_lim);

  return result;
}

#else
int SYSCALL_DMZ_setrlimit(int resource, const struct apos_rlimit* lim) {
  const struct apos_rlimit* KERNEL_lim = 0x0;

  const int CHECK_lim = syscall_verify_buffer(
      lim, sizeof(struct apos_rlimit), 0 /* is_write */, 0 /* allow_null */);
  if (CHECK_lim < 0) return CHECK_lim;

  KERNEL_lim = (const struct apos_rlimit*)kmalloc(sizeof(struct apos_rlimit));

  if (!KERNEL_lim) {
    if (KERNEL_lim) kfree((void*)KERNEL_lim);

    return -ENOMEM;
  }

  int result;
  if (lim) {
    result = syscall_copy_from_user(lim, (void*)KERNEL_lim,
                                    sizeof(struct apos_rlimit));
    if (result) goto cleanup;
  }

  result = proc_setrlimit(resource, KERNEL_lim);

  // TODO(aoates): this should only copy the written bytes, not the full kernel
  // buffer (e.g. in a read() syscall).

  goto cleanup;  // Make the compiler happy if cleanup is otherwise unused.

cleanup:
  if (KERNEL_lim) kfree((void*)KERNEL_lim);

  return result;
}
#endif

int SYSCALL_DMZ_socket(int domain, int type, int protocol) {
  int result;

  result = net_socket(domain, type, protocol);

  // TODO(aoates): this should only copy the written bytes, not the full kernel
  // buffer (e.g. in a read() syscall).

  goto cleanup;  // Make the compiler happy if cleanup is otherwise unused.

cleanup:

  return result;
}

int SYSCALL_DMZ_shutdown(int socket, int how) {
  int result;

  result = net_shutdown(socket, how);

  // TODO(aoates): this should only copy the written bytes, not the full kernel
  // buffer (e.g. in a read() syscall).

  goto cleanup;  // Make the compiler happy if cleanup is otherwise unused.

cleanup:

  return result;
}

int SYSCALL_DMZ_bind(int socket, const struct sockaddr* addr,
                     socklen_t addr_len) {
  const struct sockaddr* KERNEL_addr = 0x0;

  const int CHECK_addr = syscall_verify_buffer(addr, addr_len, 0 /* is_write */,
                                               0 /* allow_null */);
  if (CHECK_addr < 0) return CHECK_addr;

  KERNEL_addr = (const struct sockaddr*)kmalloc(addr_len);

  if (!KERNEL_addr) {
    if (KERNEL_addr) kfree((void*)KERNEL_addr);

    return -ENOMEM;
  }

  int result;
  if (addr) {
    result = syscall_copy_from_user(addr, (void*)KERNEL_addr, addr_len);
    if (result) goto cleanup;
  }

  result = net_bind(socket, KERNEL_addr, addr_len);

  // TODO(aoates): this should only copy the written bytes, not the full kernel
  // buffer (e.g. in a read() syscall).

  goto cleanup;  // Make the compiler happy if cleanup is otherwise unused.

cleanup:
  if (KERNEL_addr) kfree((void*)KERNEL_addr);

  return result;
}

int SYSCALL_DMZ_listen(int socket, int backlog) {
  int result;

  result = net_listen(socket, backlog);

  // TODO(aoates): this should only copy the written bytes, not the full kernel
  // buffer (e.g. in a read() syscall).

  goto cleanup;  // Make the compiler happy if cleanup is otherwise unused.

cleanup:

  return result;
}

int SYSCALL_DMZ_accept(int socket, struct sockaddr* addr, socklen_t* addr_len) {
  socklen_t* KERNEL_addr_len = 0x0;

  const int CHECK_addr_len = syscall_verify_buffer(
      addr_len, sizeof(socklen_t), 1 /* is_write */, 1 /* allow_null */);
  if (CHECK_addr_len < 0) return CHECK_addr_len;

  KERNEL_addr_len = !addr_len ? 0x0 : (socklen_t*)kmalloc(sizeof(socklen_t));

  if ((addr_len && !KERNEL_addr_len)) {
    if (KERNEL_addr_len) kfree((void*)KERNEL_addr_len);

    return -ENOMEM;
  }

  int result;
  if (addr_len) {
    result = syscall_copy_from_user(addr_len, (void*)KERNEL_addr_len,
                                    sizeof(socklen_t));
    if (result) goto cleanup;
  }

  result = accept_wrapper(socket, addr, KERNEL_addr_len);

  // TODO(aoates): this should only copy the written bytes, not the full kernel
  // buffer (e.g. in a read() syscall).
  if (addr_len) {
    int copy_result =
        syscall_copy_to_user(KERNEL_addr_len, addr_len, sizeof(socklen_t));
    if (copy_result) {
      result = copy_result;
      goto cleanup;
    }
  }

  goto cleanup;  // Make the compiler happy if cleanup is otherwise unused.

cleanup:
  if (KERNEL_addr_len) kfree((void*)KERNEL_addr_len);

  return result;
}

int SYSCALL_DMZ_connect(int socket, const struct sockaddr* addr,
                        socklen_t addr_len) {
  const struct sockaddr* KERNEL_addr = 0x0;

  const int CHECK_addr = syscall_verify_buffer(addr, addr_len, 0 /* is_write */,
                                               0 /* allow_null */);
  if (CHECK_addr < 0) return CHECK_addr;

  KERNEL_addr = (const struct sockaddr*)kmalloc(addr_len);

  if (!KERNEL_addr) {
    if (KERNEL_addr) kfree((void*)KERNEL_addr);

    return -ENOMEM;
  }

  int result;
  if (addr) {
    result = syscall_copy_from_user(addr, (void*)KERNEL_addr, addr_len);
    if (result) goto cleanup;
  }

  result = net_connect(socket, KERNEL_addr, addr_len);

  // TODO(aoates): this should only copy the written bytes, not the full kernel
  // buffer (e.g. in a read() syscall).

  goto cleanup;  // Make the compiler happy if cleanup is otherwise unused.

cleanup:
  if (KERNEL_addr) kfree((void*)KERNEL_addr);

  return result;
}

ssize_t SYSCALL_DMZ_recv(int socket, void* buf, size_t len, int flags) {
  void* KERNEL_buf = 0x0;

  const int CHECK_buf =
      syscall_verify_buffer(buf, len, 1 /* is_write */, 0 /* allow_null */);
  if (CHECK_buf < 0) return CHECK_buf;

  KERNEL_buf = (void*)kmalloc(len);

  if (!KERNEL_buf) {
    if (KERNEL_buf) kfree((void*)KERNEL_buf);

    return -ENOMEM;
  }

  int result;

  result = net_recv(socket, KERNEL_buf, len, flags);

  // TODO(aoates): this should only copy the written bytes, not the full kernel
  // buffer (e.g. in a read() syscall).
  if (buf) {
    int copy_result = syscall_copy_to_user(KERNEL_buf, buf, len);
    if (copy_result) {
      result = copy_result;
      goto cleanup;
    }
  }

  goto cleanup;  // Make the compiler happy if cleanup is otherwise unused.

cleanup:
  if (KERNEL_buf) kfree((void*)KERNEL_buf);

  return result;
}

ssize_t SYSCALL_DMZ_recvfrom(int socket, void* buf, size_t len, int flags,
                             struct sockaddr* address, socklen_t* address_len) {
  void* KERNEL_buf = 0x0;
  socklen_t* KERNEL_address_len = 0x0;

  const int CHECK_buf =
      syscall_verify_buffer(buf, len, 1 /* is_write */, 0 /* allow_null */);
  if (CHECK_buf < 0) return CHECK_buf;
  const int CHECK_address_len = syscall_verify_buffer(
      address_len, sizeof(socklen_t), 1 /* is_write */, 1 /* allow_null */);
  if (CHECK_address_len < 0) return CHECK_address_len;

  KERNEL_buf = (void*)kmalloc(len);
  KERNEL_address_len =
      !address_len ? 0x0 : (socklen_t*)kmalloc(sizeof(socklen_t));

  if (!KERNEL_buf || (address_len && !KERNEL_address_len)) {
    if (KERNEL_buf) kfree((void*)KERNEL_buf);
    if (KERNEL_address_len) kfree((void*)KERNEL_address_len);

    return -ENOMEM;
  }

  int result;
  if (address_len) {
    result = syscall_copy_from_user(address_len, (void*)KERNEL_address_len,
                                    sizeof(socklen_t));
    if (result) goto cleanup;
  }

  result = recvfrom_wrapper(socket, KERNEL_buf, len, flags, address,
                            KERNEL_address_len);

  // TODO(aoates): this should only copy the written bytes, not the full kernel
  // buffer (e.g. in a read() syscall).
  if (buf) {
    int copy_result = syscall_copy_to_user(KERNEL_buf, buf, len);
    if (copy_result) {
      result = copy_result;
      goto cleanup;
    }
  }
  if (address_len) {
    int copy_result = syscall_copy_to_user(KERNEL_address_len, address_len,
                                           sizeof(socklen_t));
    if (copy_result) {
      result = copy_result;
      goto cleanup;
    }
  }

  goto cleanup;  // Make the compiler happy if cleanup is otherwise unused.

cleanup:
  if (KERNEL_buf) kfree((void*)KERNEL_buf);
  if (KERNEL_address_len) kfree((void*)KERNEL_address_len);

  return result;
}

ssize_t SYSCALL_DMZ_send(int socket, const void* buf, size_t len, int flags) {
  const void* KERNEL_buf = 0x0;

  const int CHECK_buf =
      syscall_verify_buffer(buf, len, 0 /* is_write */, 0 /* allow_null */);
  if (CHECK_buf < 0) return CHECK_buf;

  KERNEL_buf = (const void*)kmalloc(len);

  if (!KERNEL_buf) {
    if (KERNEL_buf) kfree((void*)KERNEL_buf);

    return -ENOMEM;
  }

  int result;
  if (buf) {
    result = syscall_copy_from_user(buf, (void*)KERNEL_buf, len);
    if (result) goto cleanup;
  }

  result = net_send(socket, KERNEL_buf, len, flags);

  // TODO(aoates): this should only copy the written bytes, not the full kernel
  // buffer (e.g. in a read() syscall).

  goto cleanup;  // Make the compiler happy if cleanup is otherwise unused.

cleanup:
  if (KERNEL_buf) kfree((void*)KERNEL_buf);

  return result;
}

ssize_t SYSCALL_DMZ_sendto(int socket, const void* buf, size_t len, int flags,
                           const struct sockaddr* dest_addr,
                           socklen_t dest_len) {
  const void* KERNEL_buf = 0x0;
  const struct sockaddr* KERNEL_dest_addr = 0x0;

  const int CHECK_buf =
      syscall_verify_buffer(buf, len, 0 /* is_write */, 0 /* allow_null */);
  if (CHECK_buf < 0) return CHECK_buf;
  const int CHECK_dest_addr = syscall_verify_buffer(
      dest_addr, dest_len, 0 /* is_write */, 1 /* allow_null */);
  if (CHECK_dest_addr < 0) return CHECK_dest_addr;

  KERNEL_buf = (const void*)kmalloc(len);
  KERNEL_dest_addr =
      !dest_addr ? 0x0 : (const struct sockaddr*)kmalloc(dest_len);

  if (!KERNEL_buf || (dest_addr && !KERNEL_dest_addr)) {
    if (KERNEL_buf) kfree((void*)KERNEL_buf);
    if (KERNEL_dest_addr) kfree((void*)KERNEL_dest_addr);

    return -ENOMEM;
  }

  int result;
  if (buf) {
    result = syscall_copy_from_user(buf, (void*)KERNEL_buf, len);
    if (result) goto cleanup;
  }
  if (dest_addr) {
    result =
        syscall_copy_from_user(dest_addr, (void*)KERNEL_dest_addr, dest_len);
    if (result) goto cleanup;
  }

  result =
      net_sendto(socket, KERNEL_buf, len, flags, KERNEL_dest_addr, dest_len);

  // TODO(aoates): this should only copy the written bytes, not the full kernel
  // buffer (e.g. in a read() syscall).

  goto cleanup;  // Make the compiler happy if cleanup is otherwise unused.

cleanup:
  if (KERNEL_buf) kfree((void*)KERNEL_buf);
  if (KERNEL_dest_addr) kfree((void*)KERNEL_dest_addr);

  return result;
}

int SYSCALL_DMZ_apos_klog(const char* msg) {
  const char* KERNEL_msg = 0x0;

  const int SIZE_msg = syscall_verify_string(msg);
  if (SIZE_msg < 0) return SIZE_msg;

  KERNEL_msg = (const char*)kmalloc(SIZE_msg);

  if (!KERNEL_msg) {
    if (KERNEL_msg) kfree((void*)KERNEL_msg);

    return -ENOMEM;
  }

  int result;
  if (msg) {
    result = syscall_copy_from_user(msg, (void*)KERNEL_msg, SIZE_msg);
    if (result) goto cleanup;
  }

  result = klog_wrapper(KERNEL_msg);

  // TODO(aoates): this should only copy the written bytes, not the full kernel
  // buffer (e.g. in a read() syscall).

  goto cleanup;  // Make the compiler happy if cleanup is otherwise unused.

cleanup:
  if (KERNEL_msg) kfree((void*)KERNEL_msg);

  return result;
}

int SYSCALL_DMZ_apos_run_ktest(const char* name) {
  const char* KERNEL_name = 0x0;

  const int SIZE_name = syscall_verify_string(name);
  if (SIZE_name < 0) return SIZE_name;

  KERNEL_name = (const char*)kmalloc(SIZE_name);

  if (!KERNEL_name) {
    if (KERNEL_name) kfree((void*)KERNEL_name);

    return -ENOMEM;
  }

  int result;
  if (name) {
    result = syscall_copy_from_user(name, (void*)KERNEL_name, SIZE_name);
    if (result) goto cleanup;
  }

  result = kernel_run_ktest(KERNEL_name);

  // TODO(aoates): this should only copy the written bytes, not the full kernel
  // buffer (e.g. in a read() syscall).

  goto cleanup;  // Make the compiler happy if cleanup is otherwise unused.

cleanup:
  if (KERNEL_name) kfree((void*)KERNEL_name);

  return result;
}

int SYSCALL_DMZ_apos_thread_create(apos_uthread_id_t* id, void* stack,
                                   void* entry) {
  apos_uthread_id_t* KERNEL_id = 0x0;

  const int CHECK_id = syscall_verify_buffer(
      id, sizeof(apos_uthread_id_t), 1 /* is_write */, 0 /* allow_null */);
  if (CHECK_id < 0) return CHECK_id;

  KERNEL_id = (apos_uthread_id_t*)kmalloc(sizeof(apos_uthread_id_t));

  if (!KERNEL_id) {
    if (KERNEL_id) kfree((void*)KERNEL_id);

    return -ENOMEM;
  }

  int result;

  result = proc_thread_create_user(KERNEL_id, stack, entry);

  // TODO(aoates): this should only copy the written bytes, not the full kernel
  // buffer (e.g. in a read() syscall).
  if (id) {
    int copy_result =
        syscall_copy_to_user(KERNEL_id, id, sizeof(apos_uthread_id_t));
    if (copy_result) {
      result = copy_result;
      goto cleanup;
    }
  }

  goto cleanup;  // Make the compiler happy if cleanup is otherwise unused.

cleanup:
  if (KERNEL_id) kfree((void*)KERNEL_id);

  return result;
}

int SYSCALL_DMZ_apos_thread_exit(void) {
  int result;

  result = proc_thread_exit_user();

  // TODO(aoates): this should only copy the written bytes, not the full kernel
  // buffer (e.g. in a read() syscall).

  goto cleanup;  // Make the compiler happy if cleanup is otherwise unused.

cleanup:

  return result;
}

int SYSCALL_DMZ_sigwait(const ksigset_t* sigmask, int* sig) {
  const ksigset_t* KERNEL_sigmask = 0x0;
  int* KERNEL_sig = 0x0;

  const int CHECK_sigmask = syscall_verify_buffer(
      sigmask, sizeof(ksigset_t), 0 /* is_write */, 0 /* allow_null */);
  if (CHECK_sigmask < 0) return CHECK_sigmask;
  const int CHECK_sig = syscall_verify_buffer(
      sig, sizeof(int), 1 /* is_write */, 0 /* allow_null */);
  if (CHECK_sig < 0) return CHECK_sig;

  KERNEL_sigmask = (const ksigset_t*)kmalloc(sizeof(ksigset_t));
  KERNEL_sig = (int*)kmalloc(sizeof(int));

  if (!KERNEL_sigmask || !KERNEL_sig) {
    if (KERNEL_sigmask) kfree((void*)KERNEL_sigmask);
    if (KERNEL_sig) kfree((void*)KERNEL_sig);

    return -ENOMEM;
  }

  int result;
  if (sigmask) {
    result = syscall_copy_from_user(sigmask, (void*)KERNEL_sigmask,
                                    sizeof(ksigset_t));
    if (result) goto cleanup;
  }

  result = proc_sigwait(KERNEL_sigmask, KERNEL_sig);

  // TODO(aoates): this should only copy the written bytes, not the full kernel
  // buffer (e.g. in a read() syscall).
  if (sig) {
    int copy_result = syscall_copy_to_user(KERNEL_sig, sig, sizeof(int));
    if (copy_result) {
      result = copy_result;
      goto cleanup;
    }
  }

  goto cleanup;  // Make the compiler happy if cleanup is otherwise unused.

cleanup:
  if (KERNEL_sigmask) kfree((void*)KERNEL_sigmask);
  if (KERNEL_sig) kfree((void*)KERNEL_sig);

  return result;
}

int SYSCALL_DMZ_apos_thread_kill(const apos_uthread_id_t* id, int sig) {
  const apos_uthread_id_t* KERNEL_id = 0x0;

  const int CHECK_id = syscall_verify_buffer(
      id, sizeof(apos_uthread_id_t), 0 /* is_write */, 0 /* allow_null */);
  if (CHECK_id < 0) return CHECK_id;

  KERNEL_id = (const apos_uthread_id_t*)kmalloc(sizeof(apos_uthread_id_t));

  if (!KERNEL_id) {
    if (KERNEL_id) kfree((void*)KERNEL_id);

    return -ENOMEM;
  }

  int result;
  if (id) {
    result =
        syscall_copy_from_user(id, (void*)KERNEL_id, sizeof(apos_uthread_id_t));
    if (result) goto cleanup;
  }

  result = proc_thread_kill_user(KERNEL_id, sig);

  // TODO(aoates): this should only copy the written bytes, not the full kernel
  // buffer (e.g. in a read() syscall).

  goto cleanup;  // Make the compiler happy if cleanup is otherwise unused.

cleanup:
  if (KERNEL_id) kfree((void*)KERNEL_id);

  return result;
}

int SYSCALL_DMZ_apos_thread_self(apos_uthread_id_t* id) {
  apos_uthread_id_t* KERNEL_id = 0x0;

  const int CHECK_id = syscall_verify_buffer(
      id, sizeof(apos_uthread_id_t), 1 /* is_write */, 0 /* allow_null */);
  if (CHECK_id < 0) return CHECK_id;

  KERNEL_id = (apos_uthread_id_t*)kmalloc(sizeof(apos_uthread_id_t));

  if (!KERNEL_id) {
    if (KERNEL_id) kfree((void*)KERNEL_id);

    return -ENOMEM;
  }

  int result;

  result = proc_thread_self(KERNEL_id);

  // TODO(aoates): this should only copy the written bytes, not the full kernel
  // buffer (e.g. in a read() syscall).
  if (id) {
    int copy_result =
        syscall_copy_to_user(KERNEL_id, id, sizeof(apos_uthread_id_t));
    if (copy_result) {
      result = copy_result;
      goto cleanup;
    }
  }

  goto cleanup;  // Make the compiler happy if cleanup is otherwise unused.

cleanup:
  if (KERNEL_id) kfree((void*)KERNEL_id);

  return result;
}

int SYSCALL_DMZ_futex_ts(uint32_t* uaddr, int op, uint32_t val,
                         const struct apos_timespec* timespec, uint32_t* uaddr2,
                         uint32_t val3) {
  const struct apos_timespec* KERNEL_timespec = 0x0;

  const int CHECK_timespec =
      syscall_verify_buffer(timespec, sizeof(struct apos_timespec),
                            0 /* is_write */, 1 /* allow_null */);
  if (CHECK_timespec < 0) return CHECK_timespec;

  KERNEL_timespec =
      !timespec
          ? 0x0
          : (const struct apos_timespec*)kmalloc(sizeof(struct apos_timespec));

  if ((timespec && !KERNEL_timespec)) {
    if (KERNEL_timespec) kfree((void*)KERNEL_timespec);

    return -ENOMEM;
  }

  int result;
  if (timespec) {
    result = syscall_copy_from_user(timespec, (void*)KERNEL_timespec,
                                    sizeof(struct apos_timespec));
    if (result) goto cleanup;
  }

  result = futex_op(uaddr, op, val, KERNEL_timespec, uaddr2, val3);

  // TODO(aoates): this should only copy the written bytes, not the full kernel
  // buffer (e.g. in a read() syscall).

  goto cleanup;  // Make the compiler happy if cleanup is otherwise unused.

cleanup:
  if (KERNEL_timespec) kfree((void*)KERNEL_timespec);

  return result;
}

int SYSCALL_DMZ_mount(const char* source, const char* mount_path,
                      const char* type, unsigned long flags, const void* data,
                      size_t data_len) {
  const char* KERNEL_source = 0x0;
  const char* KERNEL_mount_path = 0x0;
  const char* KERNEL_type = 0x0;
  const void* KERNEL_data = 0x0;

  const int SIZE_source = syscall_verify_string(source);
  if (SIZE_source < 0) return SIZE_source;
  const int SIZE_mount_path = syscall_verify_string(mount_path);
  if (SIZE_mount_path < 0) return SIZE_mount_path;
  const int SIZE_type = syscall_verify_string(type);
  if (SIZE_type < 0) return SIZE_type;
  const int CHECK_data = syscall_verify_buffer(data, data_len, 0 /* is_write */,
                                               1 /* allow_null */);
  if (CHECK_data < 0) return CHECK_data;

  KERNEL_source = (const char*)kmalloc(SIZE_source);
  KERNEL_mount_path = (const char*)kmalloc(SIZE_mount_path);
  KERNEL_type = (const char*)kmalloc(SIZE_type);
  KERNEL_data = !data ? 0x0 : (const void*)kmalloc(data_len);

  if (!KERNEL_source || !KERNEL_mount_path || !KERNEL_type ||
      (data && !KERNEL_data)) {
    if (KERNEL_source) kfree((void*)KERNEL_source);
    if (KERNEL_mount_path) kfree((void*)KERNEL_mount_path);
    if (KERNEL_type) kfree((void*)KERNEL_type);
    if (KERNEL_data) kfree((void*)KERNEL_data);

    return -ENOMEM;
  }

  int result;
  if (source) {
    result = syscall_copy_from_user(source, (void*)KERNEL_source, SIZE_source);
    if (result) goto cleanup;
  }
  if (mount_path) {
    result = syscall_copy_from_user(mount_path, (void*)KERNEL_mount_path,
                                    SIZE_mount_path);
    if (result) goto cleanup;
  }
  if (type) {
    result = syscall_copy_from_user(type, (void*)KERNEL_type, SIZE_type);
    if (result) goto cleanup;
  }
  if (data) {
    result = syscall_copy_from_user(data, (void*)KERNEL_data, data_len);
    if (result) goto cleanup;
  }

  result = vfs_mount(KERNEL_source, KERNEL_mount_path, KERNEL_type, flags,
                     KERNEL_data, data_len);

  // TODO(aoates): this should only copy the written bytes, not the full kernel
  // buffer (e.g. in a read() syscall).

  goto cleanup;  // Make the compiler happy if cleanup is otherwise unused.

cleanup:
  if (KERNEL_source) kfree((void*)KERNEL_source);
  if (KERNEL_mount_path) kfree((void*)KERNEL_mount_path);
  if (KERNEL_type) kfree((void*)KERNEL_type);
  if (KERNEL_data) kfree((void*)KERNEL_data);

  return result;
}

int SYSCALL_DMZ_unmount(const char* mount_path, unsigned long flags) {
  const char* KERNEL_mount_path = 0x0;

  const int SIZE_mount_path = syscall_verify_string(mount_path);
  if (SIZE_mount_path < 0) return SIZE_mount_path;

  KERNEL_mount_path = (const char*)kmalloc(SIZE_mount_path);

  if (!KERNEL_mount_path) {
    if (KERNEL_mount_path) kfree((void*)KERNEL_mount_path);

    return -ENOMEM;
  }

  int result;
  if (mount_path) {
    result = syscall_copy_from_user(mount_path, (void*)KERNEL_mount_path,
                                    SIZE_mount_path);
    if (result) goto cleanup;
  }

  result = vfs_unmount(KERNEL_mount_path, flags);

  // TODO(aoates): this should only copy the written bytes, not the full kernel
  // buffer (e.g. in a read() syscall).

  goto cleanup;  // Make the compiler happy if cleanup is otherwise unused.

cleanup:
  if (KERNEL_mount_path) kfree((void*)KERNEL_mount_path);

  return result;
}
