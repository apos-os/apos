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

// Forward declarations for all tests.
#ifndef APOO_ALL_TESTS_H
#define APOO_ALL_TESTS_H

#include "common/config.h"

void interrupt_clobber_test(void);
void interrupt_save_test(void);
void kmalloc_test(void);
void kprintf_test(void);
void kstring_test(void);
void ktest_test(void);
void kassert_test(void);
void kthread_test(void);
void page_alloc_map_test(void);
void page_alloc_test(void);
void ld_test(void);
void hashtable_test(void);
void ramdisk_test(void);
void ata_test(void);
void slab_alloc_test(void);
void kthread_pool_test(void);
void flag_printf_test(void);
void ramfs_test(void);
void vfs_mode_test(void);
void vfs_mount_test(void);
void vfs_test(void);
void hash_test(void);
void block_cache_test(void);
void list_test(void);
void mmap_test(void);
void vm_test(void);
void dmz_test(void);
void proc_load_test(void);
void fork_test(void);
void signal_test(void);
void user_test(void);
void proc_group_test(void);
void exec_test(void);
void cbfs_test(void);
void ansi_escape_test(void);
void circbuf_test(void);
void fifo_test(void);
void vfs_fifo_test(void);
void session_test(void);
void tty_test(void);
void wait_test(void);
void vterm_test(void);
void poll_test(void);
void limit_test(void);
void socket_test(void);
void socket_unix_test(void);
void socket_raw_test(void);
void socket_udp_test(void);
void run_user_tests(void);
void proc_thread_test(void);
void futex_test(void);
void devicetree_test(void);
void tcp_test(void);
void tuntap_test(void);

#if ENABLE_NVME
void nvme_test(void);
#endif

#if ARCH == ARCH_riscv64
void rsv64_user_test(void);
#endif

int kernel_run_ktest(const char* name);

#endif
