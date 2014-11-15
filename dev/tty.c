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
#include "dev/ld.h"
#include "dev/tty.h"
#include "memory/kmalloc.h"

apos_dev_t tty_create(ld_t* ld) {
  char_dev_t* ld_char_dev = (char_dev_t*)kmalloc(sizeof(char_dev_t));
  ld_init_char_dev(ld, ld_char_dev);
  apos_dev_t dev = makedev(DEVICE_MAJOR_TTY, DEVICE_ID_UNKNOWN);
  KASSERT(0 == dev_register_char(ld_char_dev, &dev));
  return dev;
}
