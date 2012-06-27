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

#include "kassert.h"
#include "klog.h"
#include "kmalloc.h"
#include "kstring.h"
#include "memory.h"
#include "page_alloc.h"

const uint32_t kScreenWidth = 80;
const uint32_t kScreenHeight = 24;

// VIRTUAL address of the framebuffer.
static unsigned char* const videoram = (char *)0xC00B8000;
static uint32_t cursor = 0;

void clear() {
  cursor = 0;
  uint32_t i, j;
  for (i = 0; i < kScreenWidth * kScreenHeight; ++i) {
    videoram[i*2] = ' ';
    videoram[i*2+1] = 0x07;
  }
}

void print(const char* msg) {
  klog(msg);
  int i = 0;
  while (*msg) {
    if (*msg == '\n') {
      cursor = ((cursor / kScreenWidth) + 1) * kScreenWidth - 1;
    } else {
      videoram[cursor*2] = *msg;
      videoram[cursor*2+1] = 0x07; /* light grey (7) on black (0). */
    }
    ++msg;
    ++cursor;
  }
}

void itoa_test();
void paging_test();
void kmalloc_test();

void kmain(memory_info_t* meminfo) {
  klog("kmain()\n");
  klog("page_frame_alloc_init()\n");
  set_global_meminfo(meminfo);
  page_frame_alloc_init(meminfo);
  kmalloc_init();

  clear();
  print("APOO\n");

  print("meminfo: 0x");
  print(itoa_hex((uint32_t)meminfo));
  print("\nmeminfo->kernel_start_phys: 0x"); print(itoa_hex(meminfo->kernel_start_phys));
  print("\nmeminfo->kernel_end_phys:   0x"); print(itoa_hex(meminfo->kernel_end_phys));
  print("\nmeminfo->kernel_start_virt: 0x"); print(itoa_hex(meminfo->kernel_start_virt));
  print("\nmeminfo->kernel_end_virt:   0x"); print(itoa_hex(meminfo->kernel_end_virt));
  print("\nmeminfo->mapped_start:      0x"); print(itoa_hex(meminfo->mapped_start));
  print("\nmeminfo->mapped_end:        0x"); print(itoa_hex(meminfo->mapped_end));
  print("\nmeminfo->lower_memory:      0x"); print(itoa_hex(meminfo->lower_memory));
  print("\nmeminfo->upper_memory:      0x"); print(itoa_hex(meminfo->upper_memory));
  print("\nmeminfo->phys_map_start:    0x"); print(itoa_hex(meminfo->phys_map_start));

  page_frame_alloc_test();
  kmalloc_test();
  //print("\n\nkmain: 0x");
  //print(itoa_hex((uint32_t)&kmain));
  //print("\nitoa_test: 0x");
  //print(itoa_hex((uint32_t)&itoa_test));

  //paging_test();
  //itoa_test();
  klog("[PASSED]");
}

void itoa_test() {
  char buf[1700];
  buf[0] = '\0';

  kstrcat(buf, "\n\nitoa() test:\n");
  kstrcat(buf, "------------\n");
  kstrcat(buf, "0: '");
  kstrcat(buf, itoa(0));
  kstrcat(buf, "'\n");

  kstrcat(buf, "1: '");
  kstrcat(buf, itoa(1));
  kstrcat(buf, "'\n");

  kstrcat(buf, "10: '");
  kstrcat(buf, itoa(10));
  kstrcat(buf, "'\n");

  kstrcat(buf, "100: '");
  kstrcat(buf, itoa(100));
  kstrcat(buf, "'\n");

  kstrcat(buf, "123: '");
  kstrcat(buf, itoa(123));
  kstrcat(buf, "'\n");

  kstrcat(buf, "1234567890: '");
  kstrcat(buf, itoa(1234567890));
  kstrcat(buf, "'\n");

  kstrcat(buf, "0x0: '");
  kstrcat(buf, itoa_hex(0x0));
  kstrcat(buf, "'\n");

  kstrcat(buf, "0x1: '");
  kstrcat(buf, itoa_hex(0x1));
  kstrcat(buf, "'\n");

  kstrcat(buf, "0xABCDEF0: '");
  kstrcat(buf, itoa_hex(0xABCDEF0));
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
  kstrcat(buf, itoa_hex(KERNEL_START_SYMBOL));
  kstrcat(buf, "\n&KERNEL_START: 0x");
  kstrcat(buf, itoa_hex(&KERNEL_START_SYMBOL));
  kstrcat(buf, "\nKERNEL_END: 0x");
  kstrcat(buf, itoa_hex(KERNEL_END_SYMBOL));
  kstrcat(buf, "\n&KERNEL_END: 0x");
  kstrcat(buf, itoa_hex(&KERNEL_END_SYMBOL));
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
    kassert(frame[i] == x);
  }
}

void page_frame_alloc_test() {
  clear();
  print("page_frame_alloc test\n");

  // Total allocator test.
  //int i = 0;
  //while (page_frame_alloc() != 0) {
  //  i++;
  //}
  //print("total allocated: ");
  //print(itoa(i));

  uint32_t page1 = page_frame_alloc();
  uint32_t page2 = page_frame_alloc();
  uint32_t page3 = page_frame_alloc();
  print("page1: 0x"); print(itoa_hex(page1)); print("\n");
  print("page2: 0x"); print(itoa_hex(page2)); print("\n");
  print("page3: 0x"); print(itoa_hex(page3)); print("\n");

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
  print("page4: 0x"); print(itoa_hex(page4)); print("\n");
  print("page5: 0x"); print(itoa_hex(page5)); print("\n");
  print("page6: 0x"); print(itoa_hex(page6)); print("\n");

  page_frame_free(page4);
  page_frame_free(page5);
  page_frame_free(page6);

  //print("double-free: should kassert");
  //page_frame_free(page4);
}

void kmalloc_test() {
  klog("initial state\n");
  klog("---------------\n");
  kmalloc_log_state();
  klog("---------------\n");

  void* x = kmalloc(128);
  klog("kmalloc(128) => ");
  klog(itoa_hex((uint32_t)x));
  klog("\n");
  kmalloc_log_state();
  klog("---------------\n");

  void* x2 = kmalloc(128);
  klog("kmalloc(128) => ");
  klog(itoa_hex((uint32_t)x2));
  klog("\n");
  kmalloc_log_state();
  klog("---------------\n");
}
