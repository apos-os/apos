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

#include "common/errno.h"
#include "common/klog.h"
#include "common/kstring.h"
#include "common/time.h"
#include "dev/devicetree/devicetree.h"
#include "dev/io.h"
#include "main/kernel.h"
#include "proc/kthread.h"

#define GFRTC_TIME_LOW 0
#define GFRTC_TIME_HIGH 4

typedef struct {
  devio_t io;
} gfrtc_t;

static bool g_gfrtc_init = false;
static gfrtc_t g_gfrtc;

int goldfish_rtc_driver(const dt_tree_t* tree, const dt_node_t* rtc,
                        const char* node_path, dt_driver_info_t* driver) {
  if (g_gfrtc_init) {
    klogfm(KL_GENERAL, WARNING, "Multiple goldfish RTC devices found\n");
    return -EEXIST;
  }

  g_gfrtc_init = true;

  klogf("Found Goldfish RTC at %s\n", node_path);

  dt_regval_t reg[5];
  int result = dt_parse_reg(rtc, reg, 5);
  if (result == 0) result = -EINVAL;
  if (result < 0) {
    klogf("Goldfish RTC %s bad reg property\n", node_path);
    return result;
  }

  g_gfrtc.io.type = IO_MEMORY;
  g_gfrtc.io.base = phys2virt(reg[0].base);
  return 0;
}

int goldfish_rtc_read(struct apos_timespec* ts) {
  if (!g_gfrtc_init) {
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
