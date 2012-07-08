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
#include "kmalloc.h"
#include "proc/kthread.h"
#include "proc/process.h"
#include "memory.h"
#include "page_alloc.h"
#include "page_fault.h"
#include "dev/ps2.h"
#include "dev/keyboard/ps2_keyboard.h"
#include "dev/keyboard/keyboard.h"
#include "dev/video/vga.h"
#include "dev/video/vterm.h"
#include "dev/timer.h"
#include "proc/scheduler.h"
#include "test/ktest.h"
#include "test/kernel_tests.h"

void pic_init();

static vterm_t* g_vterm = 0;
static video_t* g_video = 0;

void print(const char* msg) {
  while (*msg) {
    vterm_putc(g_vterm, *msg);
    ++msg;
  }
}

static void tick() {
  static uint8_t i = 0;
  static const char* beat = "oO";
  i = (i + 1) % 2;

  video_setc(g_video, 0, video_get_width(g_video)-1, beat[i]);
}

static void add_timers() {
  KASSERT(register_timer_callback(1000, &tick));
}

static void keyboard_cb(char c) {
  vterm_putc(g_vterm, c);
}

static void io_init() {
  static vkeyboard_t* kbd = 0x0;
  kbd = vkeyboard_create();
  KASSERT(ps2_keyboard_init(kbd));

  video_vga_init();
  vkeyboard_set_handler(kbd, &keyboard_cb);

  g_video = video_get_default();
  g_vterm = vterm_create(g_video);
}

void kmain(memory_info_t* meminfo) {
  klog("\n\n@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n");
  klog(    "@                          APOO                           @\n");
  klog(    "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n");
  klog("kmain()\n");
  klog("interrupts_init()\n");
  interrupts_init();
  klog("pic_init()\n");
  pic_init();
  klog("ps2_init()\n");
  ps2_init();

  enable_interrupts();

  klog("set_global_meminfo()\n");
  set_global_meminfo(meminfo);
  klog("page_frame_alloc_init()\n");
  page_frame_alloc_init(meminfo);
  klog("paging_init()\n");
  paging_init(meminfo);
  klog("kmalloc_init()\n");
  kmalloc_init();

  io_init();

  klog("timer_init()\n");
  timer_init();
  add_timers();

  klog("kthread_init()\n");
  kthread_init();
  klog("scheduler_init()\n");
  scheduler_init();
  klog("proc_init()\n");
  proc_init();

  klog("initialization finished...\n");

  vterm_clear(g_vterm);
  print("APOO\n");

  print("meminfo: 0x");
  print(utoa_hex((uint32_t)meminfo));
  print("\nmeminfo->kernel_start_phys: 0x"); print(utoa_hex(meminfo->kernel_start_phys));
  print("\nmeminfo->kernel_end_phys:   0x"); print(utoa_hex(meminfo->kernel_end_phys));
  print("\nmeminfo->kernel_start_virt: 0x"); print(utoa_hex(meminfo->kernel_start_virt));
  print("\nmeminfo->kernel_end_virt:   0x"); print(utoa_hex(meminfo->kernel_end_virt));
  print("\nmeminfo->mapped_start:      0x"); print(utoa_hex(meminfo->mapped_start));
  print("\nmeminfo->mapped_end:        0x"); print(utoa_hex(meminfo->mapped_end));
  print("\nmeminfo->lower_memory:      0x"); print(utoa_hex(meminfo->lower_memory));
  print("\nmeminfo->upper_memory:      0x"); print(utoa_hex(meminfo->upper_memory));
  print("\nmeminfo->phys_map_start:    0x"); print(utoa_hex(meminfo->phys_map_start));
  vterm_clear(g_vterm);

  ktest_begin_all();

  //ktest_test();
  kassert_test();
  page_alloc_test();
  page_alloc_map_test();
  kthread_test();
  kmalloc_test();
  interrupt_clobber_test();
  interrupt_save_test();
  kstring_test();
  kprintf_test();

  ktest_finish_all();

  //page_frame_alloc_test();
  klog("DONE\n");
}
