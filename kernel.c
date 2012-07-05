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
#include "kthread.h"
#include "memory.h"
#include "page_alloc.h"
#include "page_fault.h"
#include "dev/ps2.h"
#include "dev/keyboard/ps2_keyboard.h"
#include "dev/keyboard/keyboard.h"
#include "dev/video/vga.h"
#include "dev/video/vterm.h"
#include "dev/timer.h"
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

void utoa_test();
void paging_test();

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
  klog("kmalloc_init()\n");
  kmalloc_init();

  io_init();

  klog("timer_init()\n");
  timer_init();
  add_timers();

  klog("kthread_init()\n");
  kthread_init();

  klog("paging_init()\n");
  paging_init();

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

  page_alloc_map_test();
  //kthread_test();
  //kmalloc_test();
  // interrupt_clobber_test();

  //print("\n");
  //char buf[2];
  //buf[1] = '\0';
  //while (1) {
  //  buf[0] = read_char();
  //  print(buf);
  //}

  //ktest_test();
  //kstring_test();
  //kprintf_test();
  //page_frame_alloc_test();
  //print("\n\nkmain: 0x");
  //print(utoa_hex((uint32_t)&kmain));
  //print("\nutoa_test: 0x");
  //print(utoa_hex((uint32_t)&utoa_test));

  //paging_test();
  //utoa_test();
  klog("DONE\n");
}

void utoa_test() {
  char buf[1700];
  buf[0] = '\0';

  kstrcat(buf, "\n\nutoa() test:\n");
  kstrcat(buf, "------------\n");
  kstrcat(buf, "0: '");
  kstrcat(buf, utoa(0));
  kstrcat(buf, "'\n");

  kstrcat(buf, "1: '");
  kstrcat(buf, utoa(1));
  kstrcat(buf, "'\n");

  kstrcat(buf, "10: '");
  kstrcat(buf, utoa(10));
  kstrcat(buf, "'\n");

  kstrcat(buf, "100: '");
  kstrcat(buf, utoa(100));
  kstrcat(buf, "'\n");

  kstrcat(buf, "123: '");
  kstrcat(buf, utoa(123));
  kstrcat(buf, "'\n");

  kstrcat(buf, "1234567890: '");
  kstrcat(buf, utoa(1234567890));
  kstrcat(buf, "'\n");

  kstrcat(buf, "0x0: '");
  kstrcat(buf, utoa_hex(0x0));
  kstrcat(buf, "'\n");

  kstrcat(buf, "0x1: '");
  kstrcat(buf, utoa_hex(0x1));
  kstrcat(buf, "'\n");

  kstrcat(buf, "0xABCDEF0: '");
  kstrcat(buf, utoa_hex(0xABCDEF0));
  kstrcat(buf, "'\n");

  print(buf);
}

extern uint32_t KERNEL_START_SYMBOL;
extern uint32_t KERNEL_END_SYMBOL;
void paging_test() {
  char buf[1700];
  kstrcpy(buf, "\n\npaging test:\n");
  kstrcat(buf, "------------\n");
  kstrcat(buf, "KERNEL_START: 0x");
  kstrcat(buf, utoa_hex(KERNEL_START_SYMBOL));
  kstrcat(buf, "\n&KERNEL_START: 0x");
  kstrcat(buf, utoa_hex((uint32_t)&KERNEL_START_SYMBOL));
  kstrcat(buf, "\nKERNEL_END: 0x");
  kstrcat(buf, utoa_hex(KERNEL_END_SYMBOL));
  kstrcat(buf, "\n&KERNEL_END: 0x");
  kstrcat(buf, utoa_hex((uint32_t)&KERNEL_END_SYMBOL));
  print(buf);
}

void fill_frame(uint32_t frame_start, uint32_t x) {
  uint32_t* frame = (uint32_t*)(phys2virt(frame_start));
  for (uint32_t i = 0; i < PAGE_SIZE / 4; ++i) {
    frame[i] = x;
  }
}

void check_frame(uint32_t frame_start, uint32_t x) {
  uint32_t* frame = (uint32_t*)(phys2virt(frame_start));
  for (uint32_t i = 0; i < PAGE_SIZE / 4; ++i) {
    KASSERT(frame[i] == x);
  }
}

void page_frame_alloc_test() {
  vterm_clear(g_vterm);
  print("page_frame_alloc test\n");

  // Total allocator test.
  //int i = 0;
  //while (page_frame_alloc() != 0) {
  //  i++;
  //}
  //print("total allocated: ");
  //print(utoa(i));

  uint32_t page1 = page_frame_alloc();
  uint32_t page2 = page_frame_alloc();
  uint32_t page3 = page_frame_alloc();
  print("page1: 0x"); print(utoa_hex(page1)); print("\n");
  print("page2: 0x"); print(utoa_hex(page2)); print("\n");
  print("page3: 0x"); print(utoa_hex(page3)); print("\n");

  check_frame(page1, 0xCAFEBABE);
  check_frame(page2, 0xCAFEBABE);
  check_frame(page3, 0xCAFEBABE);

  fill_frame(page1, 0x11111111);
  fill_frame(page2, 0x22222222);
  fill_frame(page3, 0x33333333);

  check_frame(page1, 0x11111111);
  check_frame(page2, 0x22222222);
  check_frame(page3, 0x33333333);

  page_frame_free(page1);

  check_frame(page1, 0xDEADBEEF);
  check_frame(page2, 0x22222222);
  check_frame(page3, 0x33333333);

  page_frame_free(page2);
  page_frame_free(page3);

  check_frame(page1, 0xDEADBEEF);
  check_frame(page2, 0xDEADBEEF);
  check_frame(page3, 0xDEADBEEF);

  uint32_t page4 = page_frame_alloc();
  uint32_t page5 = page_frame_alloc();
  uint32_t page6 = page_frame_alloc();

  print("pages 4-6 should be equal to pages 1-3 in reverse order\n");
  print("page4: 0x"); print(utoa_hex(page4)); print("\n");
  print("page5: 0x"); print(utoa_hex(page5)); print("\n");
  print("page6: 0x"); print(utoa_hex(page6)); print("\n");

  page_frame_free(page4);
  page_frame_free(page5);
  page_frame_free(page6);

  //print("double-free: should kassert");
  //page_frame_free(page4);
}
