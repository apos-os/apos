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

// Generic IO functions that work for both PMIO and MMIO.
#ifndef APOO_DEV_IO_H
#define APOO_DEV_IO_H

#include "arch/common/io.h"
#include "arch/common/types.h"
#include "common/arch-config.h"
#include "common/attributes.h"

typedef enum {
  IO_PORT = 1,
  IO_MEMORY = 2,
} devio_type_t;

typedef struct {
  devio_type_t type;
  addr_t base;
} devio_t;

// TODO(aoates): the memory readers should be in generic and/or arch-specific.
// TODO(aoates): on architectures that don't support IO_PORT, skip the branch.

static inline ALWAYS_INLINE uint8_t io_read8(devio_t dev, addr_t addr) {
  return dev.type == IO_PORT ? inb(dev.base + addr)
                             : *(volatile uint8_t*)(dev.base + addr);
}

static inline ALWAYS_INLINE uint16_t io_read16(devio_t dev, addr_t addr) {
  return dev.type == IO_PORT ? ins(dev.base + addr)
                             : *(volatile uint16_t*)(dev.base + addr);
}

static inline ALWAYS_INLINE uint32_t io_read32(devio_t dev, addr_t addr) {
  return dev.type == IO_PORT ? inl(dev.base + addr)
                             : *(volatile uint32_t*)(dev.base + addr);
}

static inline ALWAYS_INLINE void io_write8(devio_t dev, addr_t addr,
                                           uint8_t val) {
  if (dev.type == IO_PORT)
    outb(dev.base + addr, val);
  else
    *(volatile uint8_t*)(dev.base + addr) = val;
}

static inline ALWAYS_INLINE void io_write16(devio_t dev, addr_t addr,
                                            uint16_t val) {
  if (dev.type == IO_PORT)
    outs(dev.base + addr, val);
  else
    *(volatile uint16_t*)(dev.base + addr) = val;
}

static inline ALWAYS_INLINE void io_write32(devio_t dev, addr_t addr,
                                            uint32_t val) {
  if (dev.type == IO_PORT)
    outl(dev.base + addr, val);
  else
    *(volatile uint32_t*)(dev.base + addr) = val;
}

#endif
