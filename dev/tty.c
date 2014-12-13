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

#include "common/kassert.h"
#include "dev/char_dev.h"
#include "dev/dev.h"
#include "dev/ld.h"
#include "dev/tty.h"
#include "memory/kmalloc.h"

_Static_assert(DEVICE_MAX_MINOR <= 100,
               "DEVICE_MAX_MINOR too large for the g_ttys table");
static tty_t g_ttys[DEVICE_MAX_MINOR];

apos_dev_t tty_create(ld_t* ld) {
  char_dev_t* ld_char_dev = (char_dev_t*)kmalloc(sizeof(char_dev_t));
  ld_init_char_dev(ld, ld_char_dev);
  apos_dev_t dev = makedev(DEVICE_MAJOR_TTY, DEVICE_ID_UNKNOWN);
  KASSERT(0 == dev_register_char(ld_char_dev, &dev));

  const int tty_idx = minor(dev);
  g_ttys[tty_idx].session = -1;

  return dev;
}

void tty_destroy(apos_dev_t dev) {
  if (major(dev) != DEVICE_MAJOR_TTY) {
    klogfm(KL_TTY, DFATAL, "tty_destroy() called with non-TTY device\n");
    return;
  }

  const int tty_idx = minor(dev);
  if (tty_idx <= 0 || tty_idx > DEVICE_MAX_MINOR) {
    klogfm(KL_TTY, DFATAL, "tty_destroy() called with invalid device\n");
    return;
  }

  if (g_ttys[tty_idx].session != -1) {
    klogfm(KL_TTY, DFATAL,
           "tty_destroy() called on TTY that is the controlling terminal of "
           "session %d\n",
           g_ttys[tty_idx].session);
    return;
  }

  int result = dev_unregister_char(dev);
  if (result) {
    klogfm(KL_TTY, DFATAL, "dev_unregister_char() failed in tty_destoy(): %d\n",
           result);
  }
}

tty_t* tty_get(apos_dev_t dev) {
  if (major(dev) != DEVICE_MAJOR_TTY) {
    klogfm(KL_TTY, DFATAL, "tty_get() called with non-TTY device\n");
    return NULL;
  }

  const int tty_idx = minor(dev);
  if (tty_idx < 0 || tty_idx >= DEVICE_MAX_MINOR) {
    return NULL;
  }

  return &g_ttys[tty_idx];
}
