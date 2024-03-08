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

#include "dev/dev.h"

#include "common/errno.h"
#include "common/kassert.h"
#include "common/kprintf.h"
#include "common/kstring.h"
#include "memory/kmalloc.h"
#include "memory/memobj.h"
#include "memory/memobj_block_dev.h"
#include "vfs/vfs.h"

// Names for each known device type.
static const char* kTypeNames[DEVICE_MAX_MAJOR] = {
  0x0,
  0x0,
  "ata",   // DEVICE_MAJOR_ATA
  "ram",   // DEVICE_MAJOR_RAMDISK
  "tty",   // DEVICE_MAJOR_TTY
  "nvme",  // DEVICE_MAJOR_NVME
  "tun",   // DEVICE_MAJOR_TUN
  0x0,
  0x0,
  0x0,
};

static void* g_block_devices[DEVICE_MAX_MAJOR][DEVICE_MAX_MINOR];
static memobj_t* g_block_memobjs[DEVICE_MAX_MAJOR][DEVICE_MAX_MINOR];
static void* g_char_devices[DEVICE_MAX_MAJOR][DEVICE_MAX_MINOR];
static int g_dev_fs_ready = 0;

static void make_fs_device(int vfs_type, int major, int minor);
static void remove_fs_device(int major, int minor);

static int check_register(void* dev, apos_dev_t* id) {
  if (!dev || kmajor(*id) >= DEVICE_MAX_MAJOR ||
      (kminor(*id) >= DEVICE_MAX_MINOR && kminor(*id) != DEVICE_ID_UNKNOWN)) {
    return -EINVAL;
  }
  return 0;
}

// Finds and fills the id, returning 0 on success.
static int find_id(void* array[DEVICE_MAX_MAJOR][DEVICE_MAX_MINOR],
                   apos_dev_t* id) {
  if (kminor(*id) != DEVICE_ID_UNKNOWN &&
      array[kmajor(*id)][kminor(*id)] != 0x0) {
    return -EEXIST;
  } else if (kminor(*id) == DEVICE_ID_UNKNOWN) {
    for (int i = 0; i < DEVICE_MAX_MINOR; ++i) {
      if (array[kmajor(*id)][i] == 0x0) {
        *id = kmakedev(kmajor(*id), i);
        break;
      }
    }
  }
  KASSERT(array[kmajor(*id)][kminor(*id)] == 0x0);
  return 0;
}

int dev_register_block(block_dev_t* dev, apos_dev_t* id) {
  int result = check_register(dev, id);
  if (result) {
    return result;
  }
  result = find_id(g_block_devices, id);
  if (result) {
    return result;
  }

  g_block_devices[kmajor(*id)][kminor(*id)] = dev;
  g_block_memobjs[kmajor(*id)][kminor(*id)] =
      (memobj_t*)kmalloc(sizeof(memobj_t));
  KASSERT(0 == memobj_create_block_dev(
                   g_block_memobjs[kmajor(*id)][kminor(*id)], *id));
  if (g_dev_fs_ready) {
    make_fs_device(VFS_S_IFBLK, kmajor(*id), kminor(*id));
  }
  return 0;
}

int dev_register_char(char_dev_t* dev, apos_dev_t* id) {
  int result = check_register(dev, id);
  if (result) {
    return result;
  }
  result = find_id(g_char_devices, id);
  if (result) {
    return result;
  }

  g_char_devices[kmajor(*id)][kminor(*id)] = dev;
  if (g_dev_fs_ready) {
    make_fs_device(VFS_S_IFCHR, kmajor(*id), kminor(*id));
  }
  return 0;
}

block_dev_t* dev_get_block(apos_dev_t id) {
  if (kmajor(id) >= DEVICE_MAX_MAJOR ||
      kminor(id) >= DEVICE_MAX_MINOR) {
    return 0x0;
  }
  return g_block_devices[kmajor(id)][kminor(id)];
}

char_dev_t* dev_get_char(apos_dev_t id) {
  if (kmajor(id) >= DEVICE_MAX_MAJOR ||
      kminor(id) >= DEVICE_MAX_MINOR) {
    return 0x0;
  }
  return g_char_devices[kmajor(id)][kminor(id)];
}

// TODO(aoates): return this memobj with a reference and audit everything to
// ensure no chance of dangling references.
memobj_t* dev_get_block_memobj(apos_dev_t id) {
  if (kmajor(id) >= DEVICE_MAX_MAJOR ||
      kminor(id) >= DEVICE_MAX_MINOR) {
    return 0x0;
  }
  return g_block_memobjs[kmajor(id)][kminor(id)];
}

int dev_unregister_block(apos_dev_t id) {
  if (kmajor(id) >= DEVICE_MAX_MAJOR ||
      kminor(id) >= DEVICE_MAX_MINOR) {
    return -ERANGE;
  }
  if (g_block_devices[kmajor(id)][kminor(id)] == 0x0) {
    return -ENOENT;
  }
  remove_fs_device(kmajor(id), kminor(id));

  g_block_devices[kmajor(id)][kminor(id)] = 0x0;
  kfree(g_block_memobjs[kmajor(id)][kminor(id)]);
  return 0;
}

int dev_unregister_char(apos_dev_t id) {
  if (kmajor(id) >= DEVICE_MAX_MAJOR ||
      kminor(id) >= DEVICE_MAX_MINOR) {
    return -ERANGE;
  }
  if (g_char_devices[kmajor(id)][kminor(id)] == 0x0) {
    return -ENOENT;
  }
  remove_fs_device(kmajor(id), kminor(id));

  g_char_devices[kmajor(id)][kminor(id)] = 0x0;
  return 0;
}

static void make_fs_device(int vfs_type, int major, int minor) {
  char name[512];
  if (!kTypeNames[major]) {
    klogf("warning: cannot create device node for device of "
          "unknown type (%d.%d)\n", major, minor);
    return;
  }
  ksprintf(name, "/dev/%s%d", kTypeNames[major], minor);
  const int result = vfs_mknod(name, vfs_type, kmakedev(major, minor));
  if (result < 0) {
    klogf("warning: unable to create %s: %s\n", name, errorname(-result));
  }
}

static void remove_fs_device(int major, int minor) {
  char name[512];
  if (!kTypeNames[major]) {
    klogf("warning: cannot create device node for device of "
          "unknown type (%d.%d)\n", major, minor);
    return;
  }
  ksprintf(name, "/dev/%s%d", kTypeNames[major], minor);
  const int result = vfs_unlink(name);
  if (result < 0) {
    klogf("warning: unable to remove %s: %s\n", name, errorname(-result));
  }
}

void dev_init_fs(void) {
  const int kBufSize = 512;
  vfs_mkdir("/dev", 0);

  const int dev_fd = vfs_open("/dev", VFS_O_RDONLY);
  KASSERT(dev_fd >= 0);

  // Removing existing entries.
  char buf[kBufSize];
  char* full_path = kmalloc(VFS_MAX_PATH_LENGTH);
  while (1) {
    const int len = vfs_getdents(dev_fd, (kdirent_t*)(&buf[0]), kBufSize);
    if (len < 0) {
      klogf("warning: unable to read /dev: %s\n", errorname(-len));
      vfs_close(dev_fd);
      kfree(full_path);
      return;
    }
    if (len == 0) {
      break;
    }

    int buf_offset = 0;
    while (buf_offset < len) {
      kdirent_t* ent = (kdirent_t*)(buf + buf_offset);
      buf_offset += ent->d_reclen;

      if (kstrcmp(ent->d_name, ".") == 0 ||
          kstrcmp(ent->d_name, "..") == 0) {
        continue;
      }

      ksprintf(full_path, "/dev/%s", ent->d_name);
      const int result = vfs_unlink(full_path);
      if (result < 0) {
        klogf("warning: unable to remove %s\n", full_path);
      }
    }
  }
  kfree(full_path);

  // Create new entries for each existing device.
  for (int major = 0; major < DEVICE_MAX_MAJOR; ++major) {
    for (int minor = 0; minor < DEVICE_MAX_MINOR; ++minor) {
      if (g_block_devices[major][minor]) {
        make_fs_device(VFS_S_IFBLK, major, minor);
      }
      if (g_char_devices[major][minor]) {
        make_fs_device(VFS_S_IFCHR, major, minor);
      }
    }
  }

  // TODO(aoates): there's a race condition here between other threads
  // registering devices and us setting this bit.  We should really have a mutex
  // and lock over the entire init.
  vfs_close(dev_fd);
  g_dev_fs_ready = 1;
}
