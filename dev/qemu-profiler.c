// Copyright 2025 Andrew Oates.  All Rights Reserved.
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
#include "dev/qemu-profiler.h"

#include <stdbool.h>

#include "common/errno.h"
#include "common/klog.h"
#include "common/kstring.h"
#include "common/time.h"
#include "dev/devicetree/devicetree.h"
#include "dev/io.h"
#include "main/kernel.h"
#include "proc/kthread.h"

#define QEMU_PROFILER_ENABLE 0
#define QEMU_PROFILER_PERIOD_MICROS 4

typedef struct {
  devio_t io;
} qemu_profiler_t;

static bool g_qemu_profiler_init = false;
static qemu_profiler_t g_qemu_profiler;

int qemu_profiler_driver(const dt_tree_t* tree, const dt_node_t* profiler,
                         const char* node_path, dt_driver_info_t* driver) {
  if (g_qemu_profiler_init) {
    klogfm(KL_GENERAL, WARNING, "Multiple qemu profiler devices found\n");
    return -EEXIST;
  }

  g_qemu_profiler_init = true;

  klogf("Found Qemu Profiler at %s\n", node_path);

  dt_regval_t reg[5];
  int result = dt_parse_reg(profiler, reg, 5);
  if (result == 0) result = -EINVAL;
  if (result < 0) {
    klogf("Qemu Profiler %s bad reg property\n", node_path);
    return result;
  }

  g_qemu_profiler.io.type = IO_MEMORY;
  g_qemu_profiler.io.base = phys2virt(reg[0].base);

  return 0;
}

int qemu_profiler_enable(void) {
  if (!g_qemu_profiler_init) {
    return -ENOTSUP;
  }
  // Profile every 1ms.  Note: in practice, qemu seems to only be able to poll
  // at every 1.3ms at most.
  io_write32(g_qemu_profiler.io, QEMU_PROFILER_PERIOD_MICROS, 1000);
  io_write32(g_qemu_profiler.io, QEMU_PROFILER_ENABLE, 1);
  return 0;
}

int qemu_profiler_disable(void) {
  if (!g_qemu_profiler_init) {
    return -ENOTSUP;
  }
  io_write32(g_qemu_profiler.io, QEMU_PROFILER_ENABLE, 0);
  return 0;
}
