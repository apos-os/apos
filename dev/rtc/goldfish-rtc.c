// Copyright 2023 Andrew Oates.  All Rights Reserved.
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
#include "dev/rtc/goldfish-rtc.h"

#include <stdbool.h>

#include "common/klog.h"
#include "common/kstring.h"
#include "common/time.h"
#include "dev/devicetree/devicetree.h"
#include "dev/io.h"
#include "main/kernel.h"
#include "proc/kthread.h"
#include "proc/spinlock.h"

#define GFRTC_TIME_LOW 0
#define GFRTC_TIME_HIGH 4

typedef struct {
  bool present;
  devio_t io;
} gfrtc_t;

static kspinlock_t g_spin = KSPINLOCK_NORMAL_INIT_STATIC;
static bool g_gfrtc_init = false;
static gfrtc_t g_gfrtc;

// This should probably be a shared devicetree helper.
bool dtprop_valeq(const dt_property_t* prop, const char* s) {
  return prop->val_len == (size_t)kstrlen(s) + 1 && kstrcmp(prop->val, s) == 0;
}

// Recursively look for a goldfish RTC.  If found, returns it.
static const dt_node_t* find_gfrtc(const dt_node_t* node) {
  // Is _this_ an RTC?
  const dt_property_t* compat = dt_get_prop(node, "compatible");
  if (compat && dtprop_valeq(compat, "google,goldfish-rtc")) {
    return node;
  }

  dt_node_t* child = node->children;
  while (child) {
    const dt_node_t* rtc = find_gfrtc(child);
    if (rtc) return rtc;
    child = child->next;
  }

  return NULL;
}

static void gfrtc_init(void) {
  g_gfrtc_init = true;
  g_gfrtc.present = false;
  const dt_tree_t* dtree = get_boot_info()->dtree;
  if (!dtree) return;

  const dt_node_t* rtc = find_gfrtc(dtree->root);
  if (!rtc) {
    klogf("Unable to find a Goldfish RTC\n");
    return;
  }

  char namebuf[200];
  dt_print_path(rtc, namebuf, 200);
  klogf("Found Goldfish RTC at %s\n", namebuf);

  // TODO(aoates): properly read reg using #address_cells and #size_cells rather
  // than just grabbing this out of the name.
  const char* addr_str = dt_get_unit(rtc);
  if (!*addr_str) {
    klogf("Goldfish RTC %s missing unit address\n", namebuf);
    return;
  }

  phys_addr_t addr = katou_hex(addr_str);
  g_gfrtc.io.type = IO_MEMORY;
  g_gfrtc.io.base = phys2virt(addr);
  g_gfrtc.present = true;
}

int goldfish_rtc_read(struct apos_timespec* ts) {
  kspin_lock(&g_spin);
  if (!g_gfrtc_init) {
    gfrtc_init();
  }
  kspin_unlock(&g_spin);
  // g_gfrtc is now populated and const.
  if (!g_gfrtc.present) {
    return -ENOTSUP;
  }

  // TODO(aoates): portably support 64-bit math.  Intentionally disabled only
  // for i586 so this will fail to compile if we add other 32-bit platforms that
  // might have a goldfish.
#if ARCH == ARCH_i586
  return -ENOTSUP;
#else
  uint64_t low = io_read32(g_gfrtc.io, GFRTC_TIME_LOW);
  uint64_t high = io_read32(g_gfrtc.io, GFRTC_TIME_HIGH);
  uint64_t nanos = low + (high << 32);

  ts->tv_sec = nanos / NANOS_PER_SECOND;
  ts->tv_nsec = nanos % NANOS_PER_SECOND;
  return 0;
#endif
}
