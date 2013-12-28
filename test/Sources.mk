# Copyright 2014 Andrew Oates.  All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

$(eval $(BEGIN_SOURCES))

LOCAL_SOURCES := \
  ata_test.c \
  block_cache_test.c \
  block_dev_test.c \
  dmz_test.c \
  flag_printf_test.c \
  hash_test.c \
  hashtable_test.c \
  interrupt_test.c \
  fork_test.c \
  kmalloc_test.c \
  kprintf_test.c \
  kstring_test.c \
  ktest.c \
  ktest_test.c \
  kthread_pool_test.c \
  kthread_test.c \
  ld_test.c \
  list_test.c \
  load_test.c \
  mmap_test.c \
  page_alloc_map_test.c \
  page_alloc_test.c \
  proc_group_test.c \
  ramdisk_test.c \
  ramfs_test.c \
  signal_test.c \
  slab_alloc_test.c \
  user_test.c \
  vm_test.c \
  vfs_test.c \

$(eval $(END_SOURCES))
