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

#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>

#include "arch/common/debug.h"
#include "arch/common/io.h"
#include "common/arch-config.h"
#include "common/kassert.h"
#include "common/klog.h"
#include "common/kprintf.h"
#include "memory/memory.h"

// The current logging mode.
static int g_klog_mode = KLOG_ARCH_DEBUG;
static vterm_t* g_klog_vterm = 0x0;

// The first KLOG_BUF_SIZE log characters will be saved for viewing (e.g. to
// examine the boot process).
#define KLOG_BUF_SIZE 4096
static char g_klog_history[KLOG_BUF_SIZE];
static int g_klog_len = 0;

static inline addr_t vram_start(void) {
  return get_global_meminfo()->phys_map.base + 0xB8000;
}

static klog_level_t g_global_log_level = INFO;
// Current minimum logging levels for each module.  Defaults to ERROR for each
// module.
static klog_level_t g_log_levels[KL_MODULE_MAX];
static void raw_putc(uint8_t c) {
  static uint8_t* vram = NULL;
  if (!vram) vram = (uint8_t*)vram_start();
  if (c == '\n') {
    while ((vram - (uint8_t*)vram_start()) % 160 != 0) {
      *vram++ = ' ';
      *vram++ = 0x07;
    }
  } else {
    *vram++ = c;
    *vram++ = 0x07;
  }

  // Loop it if needed.
  if (vram >= (uint8_t*)vram_start() + 160 * 24) {
    vram = (uint8_t*)vram_start();
  }
}

void klog(const char* s) {
  klogm(KL_GENERAL, INFO, s);
}

void klogf(const char* fmt, ...) {
  char buf[1024];

  va_list args;
  va_start(args, fmt);
  kvsprintf(buf, fmt, args);
  va_end(args);

  klog(buf);
}

static void klog_puts(const char* s) {
  int i = 0;
  while (s[i]) {
    arch_debug_putc(s[i]);
    switch (g_klog_mode) {
      case KLOG_ARCH_DEBUG:
        break;

      case KLOG_RAW_VIDEO:
        raw_putc(s[i]);
        break;

      case KLOG_VTERM:
        if (s[i] == '\n')
          vterm_putc(g_klog_vterm, '\r');
        vterm_putc(g_klog_vterm, s[i]);
        break;
    }
    if (g_klog_len < KLOG_BUF_SIZE) {
      g_klog_history[g_klog_len++] = s[i];
    }
    i++;
  }
}

void klogm(klog_module_t module, klog_level_t level, const char* s) {
  if (level == DFATAL) {
    if (ENABLE_KERNEL_SAFETY_NETS) level = FATAL;
    else level = ERROR;
  }

  if (!klog_enabled(module, level)) {
    return;
  }

  switch (level) {
    case FATAL: klog_puts("FATAL: "); break;
    case ERROR: klog_puts("ERROR: "); break;
    case WARNING: klog_puts("WARNING: "); break;
    default: break;
  }

  klog_puts(s);

  if (level == FATAL)
    die("fatal error");
}

void klogfm(klog_module_t module, klog_level_t level, const char* fmt, ...) {
  char buf[1024];

  va_list args;
  va_start(args, fmt);
  kvsprintf(buf, fmt, args);
  va_end(args);

  klogm(module, level, buf);
}

void klog_set_level(klog_level_t level) {
  g_global_log_level = level;
}

void klog_set_module_level(klog_module_t module, klog_level_t level) {
  g_log_levels[module] = level;
}

int klog_enabled(klog_module_t module, klog_level_t level) {
  return !(level > g_global_log_level && level > g_log_levels[module]);
}

void klog_set_mode(int mode) {
  // Downgrade if raw VGA isn't supported.
  if (mode == KLOG_RAW_VIDEO && !ARCH_SUPPORTS_RAW_VGA) {
    mode = KLOG_ARCH_DEBUG;
  }
  g_klog_mode = mode;
}

// Set the vterm_t to be used with KLOG_VTERM.
void klog_set_vterm(vterm_t* t) {
  g_klog_vterm = t;
}

int klog_read(int offset, void* buf, int len) {
  int bytes_read = 0;
  while (offset < g_klog_len && bytes_read < len) {
    ((char*)buf)[bytes_read++] = g_klog_history[offset++];
  }
  return bytes_read;
}
