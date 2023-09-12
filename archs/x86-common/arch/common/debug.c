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
#include "arch/common/debug.h"

#include "arch/common/io.h"

void arch_debug_putc(char c) {
  // N.B.(aoates): In principle, I think we should be checking for the busy bit
  // here and at the end, but that doesn't seem to work with the bochs parallel
  // port.
  outb(0x378, c);

  uint8_t orig = inb(0x37a);
  outb(0x37a, orig | 0x04 | 0x08);
  outb(0x37a, orig | 0x01);
  outb(0x37a, orig);
}
