// Copyright 2024 Andrew Oates.  All Rights Reserved.
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
#include "sanitizers/tsan/tsan_access.h"

#include "common/attributes.h"
#include "common/hash.h"
#include "common/kassert.h"
#include "common/kprintf.h"
#include "common/kstring.h"
#include "common/math.h"
#include "dev/interrupts.h"
#include "proc/kthread-internal.h"
#include "sanitizers/tsan/internal.h"
#include "sanitizers/tsan/report.h"
#include "sanitizers/tsan/shadow_cell.h"
#include "sanitizers/tsan/tsan.h"
#include "sanitizers/tsan/tsan_layout.h"
#include "sanitizers/tsan/tsan_params.h"

bool g_tsan_log = true;
static tsan_report_fn_t g_tsan_report_fn = NULL;

static ALWAYS_INLINE uint8_t make_mask(uint8_t offset, uint8_t size) {
  KASSERT_DBG(size > 0 && size <= 8);
  KASSERT_DBG(offset >= 0 && offset < 8);
  KASSERT_DBG(offset + size <= 8);
  return (uint8_t)(((1 << size) - 1) << offset);
}

static ALWAYS_INLINE tsan_shadow_t make_shadow(kthread_t thread, addr_t addr,
                                               uint8_t size,
                                               tsan_access_type_t type) {
  tsan_shadow_t shadow;
  shadow.epoch = thread->tsan.clock.ts[thread->tsan.sid];
  shadow.sid = thread->tsan.sid;
  shadow.mask = make_mask(addr % 8, size);
  shadow.is_write = (type == TSAN_ACCESS_WRITE);
  return shadow;
}

static ALWAYS_INLINE uint8_t shadow_offset(tsan_shadow_t s) {
  return __builtin_ctzg(s.mask);
}

static ALWAYS_INLINE uint8_t shadow_size(tsan_shadow_t s) {
  return __builtin_popcountg(s.mask);
}

static ALWAYS_INLINE tsan_shadow_t* get_shadow_cells(addr_t addr) {
  addr_t offset = (addr & ~0x7) - TSAN_HEAP_START_ADDR;
  addr_t shadow = TSAN_SHADOW_START_ADDR +
                  (offset * sizeof(tsan_shadow_t) * TSAN_SHADOW_CELLS);
  return (tsan_shadow_t*)shadow;
}

static ALWAYS_INLINE uint8_t get_shadow_mask(addr_t offset, uint8_t log_size) {
  return (uint8_t)((uint16_t)((1 << (1 << log_size)) - 1) << offset);
}

static ALWAYS_INLINE void store_shadow(tsan_shadow_t* dst, tsan_shadow_t data) {
  // TODO(tsan): this should be an atomic store.
  *dst = data;
}

// Returns true if the given access can overwrite the other given access.
static ALWAYS_INLINE bool can_overwrite(tsan_shadow_t a, tsan_shadow_t b) {
  return a.is_write || !b.is_write;
}

#define SHADOW_PRETTY_LEN 64

static char* print_shadow(char* buf, tsan_shadow_t s) {
  if (s.epoch == 0) {
    kstrcpy(buf, "0");
    return buf;
  }
  uint8_t offset = shadow_offset(s);
  uint8_t size  = shadow_size(s);
  KASSERT_DBG(__builtin_clzg(s.mask) + offset + size == 8);
  ksnprintf(buf, SHADOW_PRETTY_LEN, "{tid=%u@%u offset=%d size=%d is_write=%d}",
            (uint32_t)(s.sid), s.epoch, offset, size, s.is_write);
  return buf;
}

static const char* type2str(tsan_access_type_t t) {
  switch (t) {
    case TSAN_ACCESS_READ: return "READ";
    case TSAN_ACCESS_WRITE: return "WRITE";
  }
}

static tsan_access_type_t shadow2type(tsan_shadow_t s) {
  return s.is_write ? TSAN_ACCESS_WRITE : TSAN_ACCESS_READ;
}

static void default_report_func(const tsan_report_t* report) {
  klogfm(KL_GENERAL, FATAL,
         "TSAN: detected data race: "
         "%d-byte %s on address 0x%" PRIxADDR " at \n #0 0x%" PRIxADDR "\n"
         "Previous access was: "
         "%d-byte %s on address 0x%" PRIxADDR " at \n #0 0x%" PRIxADDR "\n",
         report->race.cur.size, type2str(report->race.cur.type),
         report->race.cur.addr, report->race.cur.pc,
         report->race.prev.size, type2str(report->race.prev.type),
         report->race.prev.addr, report->race.prev.pc);
}

static void tsan_report_race(kthread_t thread, addr_t pc, addr_t addr,
                             tsan_shadow_t old, tsan_shadow_t new) {
  char pretty_shadow[2][SHADOW_PRETTY_LEN];
  uint64_t old_u64 = *(uint64_t*)&old;
  uint64_t new_u64 = *(uint64_t*)&new;
  if (g_tsan_log) {
    klogfm(KL_GENERAL, INFO,
           "TSAN: detected data race on address %" PRIxADDR
           ": old = %s [0x%lx], new = %s [0x%lx]\n",
           addr, print_shadow(pretty_shadow[0], old), old_u64,
           print_shadow(pretty_shadow[1], new), new_u64);
  }

  // Build a report.
  KASSERT_DBG(addr == ((addr & ~0x7) + shadow_offset(new)));
  tsan_report_t report;
  report.race.cur.addr = addr;
  report.race.cur.pc = pc;
  report.race.cur.size = shadow_size(new);
  report.race.cur.type = shadow2type(new);

  report.race.prev.addr = (addr & ~0x7) + shadow_offset(old);
  report.race.prev.pc = 0;
  report.race.prev.size = shadow_size(old);
  report.race.prev.type = shadow2type(old);

  PUSH_AND_DISABLE_INTERRUPTS();
  tsan_report_fn_t fn = g_tsan_report_fn ? g_tsan_report_fn :
      default_report_func;
  POP_INTERRUPTS();

  fn(&report);
}

bool tsan_check(addr_t pc, addr_t addr, uint8_t size, tsan_access_type_t type) {
  if (!g_tsan_init) return false;

  if (addr < TSAN_HEAP_START_ADDR || addr >= TSAN_HEAP_START_ADDR +
      TSAN_HEAP_LEN_ADDR) {
    // Access outside the heap.  Ignore.
    return false;
  }

  // The access should fit within a single shadow cell.
  KASSERT((addr & ~0x7) == ((addr + size - 1) & ~0x7));

  PUSH_AND_DISABLE_INTERRUPTS();
  kthread_t thread = kthread_current_thread();
  tsan_shadow_t shadow = make_shadow(thread, addr, size, type);

  tsan_shadow_t* shadow_mem = get_shadow_cells(addr);
  if (g_tsan_log) {
    char pretty_shadow[4][SHADOW_PRETTY_LEN];
    klogf("#%d: Access: %d@%d %p/%zd typ=0x%x {%s, %s, %s, %s}\n", thread->id,
          thread->tsan.sid, thread->tsan.clock.ts[thread->tsan.sid],
          (void*)addr, (ssize_t)size, (int)type,
          print_shadow(pretty_shadow[0], shadow_mem[0]),
          print_shadow(pretty_shadow[1], shadow_mem[1]),
          print_shadow(pretty_shadow[2], shadow_mem[2]),
          print_shadow(pretty_shadow[3], shadow_mem[3]));
  }

  // First check if the exact same access is already stored.
  for (int i = 0; i < TSAN_SHADOW_CELLS; ++i) {
    if (shadow2raw(shadow_mem[i]) == shadow2raw(shadow)) {
      POP_INTERRUPTS();
      return false;
    }
  }

  bool stored = false;
  for (int i = 0; i < TSAN_SHADOW_CELLS; ++i) {
    tsan_shadow_t old = shadow_mem[i];
    if (old.epoch == 0) {
      // Unused slot --- no need to check any more, and we can store here.
      if (!stored) {
        store_shadow(&shadow_mem[i], shadow);
      }
      POP_INTERRUPTS();
      return false;
    }
    // Check if the two accesses overlap.
    if (!(old.mask & shadow.mask)) {
      // These accesses don't overlap; safe.
      continue;
    }
    if (old.sid == shadow.sid) {
      // It was me who previously stored this.  Safe.
      KASSERT_DBG(old.epoch <= shadow.epoch);
      // Overwrite if it's the exact same access, and it's not a
      // write-replacing-read.
      if (old.mask == shadow.mask && can_overwrite(shadow, old)) {
        store_shadow(&shadow_mem[i], shadow);
        stored = true;
      }
      continue;
    }
    if (!old.is_write && !shadow.is_write) {
      // Safe, both are reads.
      continue;
    }
    if (thread->tsan.clock.ts[old.sid] >= old.epoch) {
      // Safe, we synchronized.
      continue;
    }

    tsan_report_race(thread, pc, addr, old, shadow);
  }
  if (stored) {
    POP_INTERRUPTS();
    return false;
  }

  // Store in a random slot.
  // TODO(tsan): come up with a better algorithm for picking.
  uint32_t hash[3] = {fnv_hash_addr((addr_t)thread), fnv_hash_addr(addr),
                      thread->tsan.clock.ts[thread->tsan.sid]};
  int idx = fnv_hash_array(&hash, sizeof(hash)) % TSAN_SHADOW_CELLS;
  store_shadow(&shadow_mem[idx], shadow);
  POP_INTERRUPTS();
  return false;
}

bool tsan_check_unaligned(addr_t pc, addr_t addr, uint8_t size,
                          tsan_access_type_t type) {
  addr_t offset = addr & 0x7;
  addr_t a1_end = min(offset + size, 8);
  addr_t a1_size = a1_end - offset;

  bool conflict = tsan_check(pc, addr, a1_size, type);
  if (conflict || a1_size == size) {
    return conflict;
  }

  addr_t a2_addr = (addr & ~0x7) + 8;
  addr_t a2_size = size - a1_size;
  return tsan_check(pc, a2_addr, a2_size, type);
}

void tsan_set_report_func(tsan_report_fn_t fn) {
  PUSH_AND_DISABLE_INTERRUPTS();
  g_tsan_report_fn = fn;
  POP_INTERRUPTS();
}
