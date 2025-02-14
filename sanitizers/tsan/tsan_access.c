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

#include "arch/proc/stack_trace.h"
#include "common/atomic.h"
#include "common/attributes.h"
#include "common/kassert.h"
#include "common/klog.h"
#include "common/kprintf.h"
#include "common/kstring.h"
#include "common/math.h"
#include "dev/interrupts.h"
#include "memory/memory.h"
#include "proc/kthread-internal.h"
#include "sanitizers/tsan/internal.h"
#include "sanitizers/tsan/report.h"
#include "sanitizers/tsan/shadow_cell.h"
#include "sanitizers/tsan/tsan.h"
#include "sanitizers/tsan/tsan_event.h"
#include "sanitizers/tsan/tsan_layout.h"
#include "sanitizers/tsan/tsan_params.h"
#include "sanitizers/tsan/tsan_thread.h"
#include "sanitizers/tsan/tsan_thread_slot.h"

#define HASH_H_DISABLE_TSAN
#include "common/hash.h"

bool g_tsan_log = false;
static tsan_report_fn_t g_tsan_report_fn = NULL;

// An address to trace accesses to.
static addr_t g_tsan_trace = 0;

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
  // Need to coerce these into 1 or 0 so they aren't truncated to zero.
  shadow.is_write = tsan_is_write(type);
  shadow.is_atomic = tsan_is_atomic(type);
  return shadow;
}

static ALWAYS_INLINE uint8_t shadow_offset(tsan_shadow_t s) {
  return __builtin_ctzg(s.mask);
}

static ALWAYS_INLINE uint8_t shadow_size(tsan_shadow_t s) {
  return __builtin_popcountg(s.mask);
}

static ALWAYS_INLINE tsan_shadow_t* get_shadow_cells(addr_t addr) {
  KASSERT_DBG(addr >= TSAN_MAPPED_START_ADDR &&
              addr - TSAN_MAPPED_LEN_ADDR < TSAN_MAPPED_START_ADDR);
  addr_t offset = (addr & ~0x7) - TSAN_MAPPED_START_ADDR;
  KASSERT_DBG((offset % TSAN_MEMORY_CELL_SIZE) == 0);
  addr_t shadow =
      TSAN_SHADOW_START_ADDR + (offset / TSAN_MEMORY_CELL_SIZE *
                                     sizeof(tsan_shadow_t) * TSAN_SHADOW_CELLS);
  return (tsan_shadow_t*)shadow;
}

static ALWAYS_INLINE tsan_page_metadata_t* get_page_md(addr_t addr) {
  addr_t heap_page = (addr - TSAN_MAPPED_START_ADDR) / PAGE_SIZE;
  addr_t md_addr =
      TSAN_PAGE_METADATA_START + (heap_page * sizeof(tsan_page_metadata_t));
  return (tsan_page_metadata_t*)md_addr;
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
  ksnprintf(buf, SHADOW_PRETTY_LEN,
            "{tid=%u@%u offset=%d size=%d is_write=%d is_atomic=%d}",
            (uint32_t)(s.sid), s.epoch, offset, size, s.is_write, s.is_atomic);
  return buf;
}

static const char* type2str(tsan_access_type_t t) {
  if (t & TSAN_ACCESS_READ) {
    return (t & TSAN_ACCESS_IS_ATOMIC) ? "ATOMIC READ" : "READ";
  } else if (t & TSAN_ACCESS_WRITE) {
    return (t & TSAN_ACCESS_IS_ATOMIC) ? "ATOMIC WRITE" : "WRITE";
  }
  die("bad tsan access type");
}

static tsan_access_type_t shadow2type(tsan_shadow_t s) {
  tsan_access_type_t t = s.is_write ? TSAN_ACCESS_WRITE : TSAN_ACCESS_READ;
  if (s.is_atomic) {
    t |= TSAN_ACCESS_IS_ATOMIC;
  }
  return t;
}

static void log_access(const tsan_access_t* access) {
  char thread[20];
  tsan_print_thread_id(thread, 20, access->thread_id);
  klogfm(KL_GENERAL, INFO,
         "%d-byte %s by thread %s on address 0x%" PRIxADDR " at \n",
         access->size, type2str(access->type), thread, access->addr);
  if (access->trace[0] == 0) {
    klogfm(KL_GENERAL, INFO, " ?? (unknown address)\n");
  } else {
    for (int i = 0; i < TSAN_MAX_STACK_LEN && access->trace[i] != 0; ++i) {
      klogfm(KL_GENERAL, INFO, " #%d 0x%" PRIxADDR "\n", i, access->trace[i]);
    }
  }
}

static void default_report_func(const tsan_report_t* report) {
  klogfm(KL_GENERAL, FATAL, "TSAN detected data race");
}

static void tsan_report_race(kthread_t thread, addr_t pc, addr_t addr,
                             tsan_shadow_t old, tsan_shadow_t new) {
  char pretty_shadow[2][SHADOW_PRETTY_LEN];
  uint64_t old_u64 = *(uint64_t*)&old;
  uint64_t new_u64 = *(uint64_t*)&new;
  klogfm(KL_GENERAL, INFO,
         "TSAN: detected data race on address %" PRIxADDR
         ": old = %s [0x%lx], new = %s [0x%lx]\n",
         addr, print_shadow(pretty_shadow[0], old), old_u64,
         print_shadow(pretty_shadow[1], new), new_u64);

  // Build a report.
  KASSERT_DBG(addr == ((addr & ~0x7) + shadow_offset(new)));
  tsan_report_t report;
  report.race.cur.thread_id = thread->id;
  tsan_find_access(tsan_log(thread), addr, shadow_size(new), shadow2type(new),
                   &report.race.cur);
  addr_t prev_addr = (addr & ~0x7) + shadow_offset(old);

  const tsan_tslot_t* slot = tsan_get_tslot(old.sid);
  const tsan_event_log_t* log = NULL;
  if (slot->log.earliest_epoch < old.epoch) {
    // This log contains the access.
    report.race.prev.thread_id = slot->thread_id;
    log = &slot->log;
  } else {
    // The log has been lost since the slot was reused --- we don't know what
    // thread did the access, nor can we reconstruct the backtrace :/
    report.race.prev.thread_id = -1;
  }
  tsan_find_access(log, prev_addr, shadow_size(old), shadow2type(old),
                   &report.race.prev);

  PUSH_AND_DISABLE_INTERRUPTS_NO_TSAN();
  tsan_report_fn_t fn = g_tsan_report_fn ? g_tsan_report_fn :
      default_report_func;
  POP_INTERRUPTS_NO_TSAN();

  klogfm(KL_GENERAL, INFO, "TSAN: detected data race: ");
  log_access(&report.race.cur);
  klogfm(KL_GENERAL, INFO, "Previous access was: ");
  log_access(&report.race.prev);
  fn(&report);
}

static bool tsan_check_internal(addr_t pc, addr_t addr, uint8_t size,
                                tsan_access_type_t type) {
  // RMWs should be marked as writes --- internal tracking with single-bit
  // 'is_read' bools can get subtle bugs easily otherwise.
  KASSERT_DBG(tsan_is_read(type) ^ tsan_is_write(type));
  if (addr == g_tsan_trace) {
    klogf("TSAN access traced: %d-byte %s by thread %d on address 0x%" PRIxADDR
          " at \n",
          size, type2str(type), tsan_current_thread()->id, addr);
    addr_t stack_trace[16];
    int len = get_stack_trace(stack_trace, 16);
    print_stack_trace(stack_trace, len);
  }

  if (!tsan_is_mapped_addr(addr)) {
    // Access outside the mapped areas.  Ignore.
    // Sanity checks to make sure we're not missing any important writes:
    KASSERT((type & TSAN_ACCESS_READ) ||
            addr < get_global_meminfo()->kernel.virt_base ||  // User addr
            smmap_region_in(&get_global_meminfo()->thread0_stack, addr) ||
            is_direct_mapped(addr));
    return false;
  }

  // The access should fit within a single shadow cell.
  KASSERT((addr & ~0x7) == ((addr + size - 1) & ~0x7));

  PUSH_AND_DISABLE_INTERRUPTS_NO_TSAN();
  kthread_t thread = tsan_current_thread();
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
      POP_INTERRUPTS_NO_TSAN();
      return false;
    }
  }

  bool stored = false;
  const tsan_page_metadata_t* page_md = get_page_md(addr);
  for (int i = 0; i < TSAN_SHADOW_CELLS; ++i) {
    tsan_shadow_t old = shadow_mem[i];
    if (old.epoch == 0) {
      // Unused slot --- no need to check any more, and we can store here.
      if (!stored) {
        store_shadow(&shadow_mem[i], shadow);
      }
      POP_INTERRUPTS_NO_TSAN();
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
    if (old.is_atomic && shadow.is_atomic) {
      // Safe, both are atomic.
      continue;
    }
    if (thread->tsan.clock.ts[old.sid] >= old.epoch) {
      // Safe, we synchronized.
      continue;
    }
    if (page_md->is_stack && (tsan_is_stack_stomper(old.sid) ||
                              tsan_is_stack_stomper(shadow.sid))) {
      // This is a thread's stack address, and one of the accesses is from a
      // stack-stomping thread.  It is not _definitely_ safe, but most likely is
      // harmless stack-space reuse, so suppress the race report.
      continue;
    }

    tsan_report_race(thread, pc, addr, old, shadow);
  }
  if (stored) {
    POP_INTERRUPTS_NO_TSAN();
    return false;
  }

  // Store in a random slot.
  // TODO(tsan): come up with a better algorithm for picking.
  uint32_t hash[3] = {fnv_hash_addr((addr_t)thread), fnv_hash_addr(addr),
                      thread->tsan.clock.ts[thread->tsan.sid]};
  int idx = fnv_hash_array(&hash, sizeof(hash)) % TSAN_SHADOW_CELLS;
  store_shadow(&shadow_mem[idx], shadow);
  POP_INTERRUPTS_NO_TSAN();
  return false;
}

bool tsan_check(addr_t pc, addr_t addr, uint8_t size, tsan_access_type_t type) {
  if (!g_tsan_init) return false;

  kthread_t thread = tsan_current_thread();
  tsan_log_access(tsan_log(thread), pc, addr, size, type);
  return tsan_check_internal(pc, addr, size, type);
}

bool tsan_check_atomic(addr_t pc, addr_t addr, uint8_t size,
                       tsan_access_type_t type, int memorder) {
  KASSERT_DBG(memorder == ATOMIC_RELAXED);
  if (!g_tsan_init) return false;

  kthread_t thread = tsan_current_thread();
  tsan_log_access(tsan_log(thread), pc, addr, size,
                  type | TSAN_ACCESS_IS_ATOMIC);
  return tsan_check_internal(pc, addr, size, type | TSAN_ACCESS_IS_ATOMIC);
}

bool tsan_check_unaligned(addr_t pc, addr_t addr, uint8_t size,
                          tsan_access_type_t type) {
  if (!g_tsan_init) return false;

  kthread_t thread = tsan_current_thread();
  tsan_log_access(tsan_log(thread), pc, addr, size, type);

  addr_t offset = addr & 0x7;
  addr_t a1_end = min(offset + size, 8);
  addr_t a1_size = a1_end - offset;

  bool conflict = tsan_check_internal(pc, addr, a1_size, type);
  if (conflict || a1_size == size) {
    return conflict;
  }

  addr_t a2_addr = (addr & ~0x7) + 8;
  addr_t a2_size = size - a1_size;
  return tsan_check_internal(pc, a2_addr, a2_size, type);
}

bool tsan_check_range(addr_t pc, addr_t addr, size_t len,
                      tsan_access_type_t type) {
  if (!g_tsan_init) return false;
  if (len == 0) return false;  // Unusual, but happens.

  if (pc == 0) {
    pc = CALLERPC;
  }

  kthread_t thread = tsan_current_thread();
  tsan_log_access(tsan_log(thread), pc, addr, len, type);

  // 1) access the unaligned left portion.
  addr_t offset = addr & 0x7;
  if (offset != 0) {
    addr_t a1_end = min(offset + len, 8);
    addr_t a1_size = a1_end - offset;
    if (tsan_check_internal(pc, addr, a1_size, type)) {
      return true;
    }
    addr += a1_size;
    len -= a1_size;
  }

  // 2) access as many 8-byte chunks as we can.
  while (len > 8) {
    if (tsan_check_internal(pc, addr, 8, type)) {
      return true;
    }
    addr += 8;
    len -= 8;
  }

  // 3) access the unaligned right portion.  The start is aligned to an 8-byte
  // boundary, but the length can be 0-7.
  if (len > 0) {
    return tsan_check_internal(pc, addr, len, type);
  }

  return false;
}

void tsan_set_report_func(tsan_report_fn_t fn) {
  PUSH_AND_DISABLE_INTERRUPTS_NO_TSAN();
  g_tsan_report_fn = fn;
  POP_INTERRUPTS_NO_TSAN();
}

void tsan_mark_stack(addr_t start, size_t len, bool is_stack) {
  KASSERT(start % PAGE_SIZE == 0);
  KASSERT(len % PAGE_SIZE == 0);
  KASSERT(start >= TSAN_MAPPED_START_ADDR);
  KASSERT(len < TSAN_MAPPED_LEN_ADDR);
  KASSERT(start + len - TSAN_MAPPED_LEN_ADDR < TSAN_MAPPED_START_ADDR);

  for (addr_t addr = start; addr < start + len; addr += PAGE_SIZE) {
    get_page_md(addr)->is_stack = is_stack;
  }
}
