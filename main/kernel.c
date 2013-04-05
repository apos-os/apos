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

#include <stdint.h>

#include "common/kassert.h"
#include "common/klog.h"
#include "common/kstring.h"
#include "dev/interrupts.h"
#include "memory/kmalloc.h"
#include "proc/kthread.h"
#include "proc/process.h"
#include "memory/memory.h"
#include "memory/page_alloc.h"
#include "memory/page_fault.h"
#include "dev/ps2.h"
#include "dev/keyboard/ps2_keyboard.h"
#include "dev/keyboard/keyboard.h"
#include "dev/ld.h"
#include "dev/ata/ata.h"
#include "dev/pci/pci.h"
#include "dev/video/vga.h"
#include "dev/video/vterm.h"
#include "dev/timer.h"
#include "dev/tty.h"
#include "proc/scheduler.h"
#include "vfs/vfs.h"
#include "test/ktest.h"
#include "test/kernel_tests.h"

#define LD_BUF_SIZE 1024

void pic_init();
void kshell_main(dev_t tty);

static vterm_t* g_vterm = 0;
static video_t* g_video = 0;
static dev_t g_tty_dev;

static void tick(void* arg) {
  static uint8_t i = 0;
  static const char* beat = "oO";
  i = (i + 1) % 2;

  video_setc(g_video, 0, video_get_width(g_video)-1, beat[i]);
}

static void add_timers() {
  KASSERT(0 == register_timer_callback(1000, 0, &tick, 0x0));
}

static void io_init() {
  static vkeyboard_t* kbd = 0x0;
  kbd = vkeyboard_create();
  KASSERT(ps2_keyboard_init(kbd));

  video_vga_init();
  g_video = video_get_default();
  g_vterm = vterm_create(g_video);
  klog_set_vterm(g_vterm);
  klog_set_mode(KLOG_VTERM);

  ld_t* ld = ld_create(LD_BUF_SIZE);
  ld_set_sink(ld, &vterm_putc_sink, (void*)g_vterm);

  vkeyboard_set_handler(kbd, &ld_provide_sink, (void*)ld);

  // Create a TTY device.
  g_tty_dev = tty_create(ld);
}

void kmain(memory_info_t* meminfo) {
  klog("\n\n@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n");
  klog(    "@                          APOO                           @\n");
  klog(    "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n");
  klog("interrupts_init()\n");
  interrupts_init();
  klog("pic_init()\n");
  pic_init();
  klog("ps2_init()\n");
  ps2_init();

  enable_interrupts();

  klog("proc_init_stage1()\n");
  proc_init_stage1();

  klog("set_global_meminfo()\n");
  set_global_meminfo(meminfo);
  klog("page_frame_alloc_init()\n");
  page_frame_alloc_init(meminfo);
  klog("paging_init()\n");
  paging_init(meminfo);
  klog("kmalloc_init()\n");
  kmalloc_init();

  io_init();

  klog("pci_init()\n");
  pci_init();

  klog("ata_init()\n");
  ata_init();

  klog("timer_init()\n");
  timer_init();
  add_timers();

  klog("kthread_init()\n");
  kthread_init();
  klog("scheduler_init()\n");
  scheduler_init();
  klog("proc_init_stage2()\n");
  proc_init_stage2();

  klog("vfs_init()\n");
  vfs_init();

  dev_init_fs();

  klog("initialization finished...\n");

  vterm_clear(g_vterm);
  klog("APOO\n");

  klog("meminfo: 0x");
  klog(utoa_hex((uint32_t)meminfo));
  klog("\nmeminfo->kernel_start_phys: 0x"); klog(utoa_hex(meminfo->kernel_start_phys));
  klog("\nmeminfo->kernel_end_phys:   0x"); klog(utoa_hex(meminfo->kernel_end_phys));
  klog("\nmeminfo->kernel_start_virt: 0x"); klog(utoa_hex(meminfo->kernel_start_virt));
  klog("\nmeminfo->kernel_end_virt:   0x"); klog(utoa_hex(meminfo->kernel_end_virt));
  klog("\nmeminfo->mapped_start:      0x"); klog(utoa_hex(meminfo->mapped_start));
  klog("\nmeminfo->mapped_end:        0x"); klog(utoa_hex(meminfo->mapped_end));
  klog("\nmeminfo->lower_memory:      0x"); klog(utoa_hex(meminfo->lower_memory));
  klog("\nmeminfo->upper_memory:      0x"); klog(utoa_hex(meminfo->upper_memory));
  klog("\nmeminfo->phys_map_start:    0x"); klog(utoa_hex(meminfo->phys_map_start));
  klog("\nmeminfo->phys_map_length:   0x"); klog(utoa_hex(meminfo->phys_map_length));
  klog("\n");

  kshell_main(g_tty_dev);

  //page_frame_alloc_test();
  klog("DONE\n");
}
