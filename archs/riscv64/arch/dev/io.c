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

#include "arch/common/io.h"

#include "common/kassert.h"

// TODO(riscv): elimnate remaining direct callers of these and delete them,
// statically guaranteeing they're not used.

void outb(ioport_t port, uint8_t val) {
  die("ioport IO not supported on riscv64");
}

uint8_t inb(ioport_t port) {
  die("ioport IO not supported on riscv64");
  return 0;
}

void outs(ioport_t port, uint16_t val) {
  die("ioport IO not supported on riscv64");
}

uint16_t ins(ioport_t port) {
  die("ioport IO not supported on riscv64");
  return 0;
}

void outl(ioport_t port, uint32_t val) {
  die("ioport IO not supported on riscv64");
}

uint32_t inl(ioport_t port) {
  die("ioport IO not supported on riscv64");
  return 0;
}
