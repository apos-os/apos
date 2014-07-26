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

#include "common/io.h"

void outb(ioport_t port, uint8_t val) {
  asm volatile (
      "outb %0, %1"
      :: "a"(val), "Nd"(port));
}

uint8_t inb(ioport_t port) {
  uint8_t val;
  asm volatile (
      "inb %1, %0"
      : "=a"(val) : "Nd"(port));
  return val;
}

void outs(ioport_t port, uint16_t val) {
  asm volatile (
      "outw %0, %1"
      :: "a"(val), "Nd"(port));
}

uint16_t ins(ioport_t port) {
  uint16_t val;
  asm volatile (
      "inw %1, %0"
      : "=a"(val) : "Nd"(port));
  return val;
}

void outl(ioport_t port, uint32_t val) {
  asm volatile (
      "outl %0, %1"
      :: "a"(val), "Nd"(port));
}

uint32_t inl(ioport_t port) {
  uint32_t val;
  asm volatile (
      "inl %1, %0"
      : "=a"(val) : "Nd"(port));
  return val;
}
