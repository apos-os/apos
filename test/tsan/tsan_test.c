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
#include "common/endian.h"
#include "common/kassert.h"
#include "common/kstring.h"
#include "common/kstring-tsan.h"
#include "dev/interrupts.h"
#include "dev/timer.h"
#include "memory/kmalloc.h"
#include "proc/defint.h"
#include "proc/fork.h"
#include "proc/kthread.h"
#include "proc/process.h"
#include "proc/scheduler.h"
#include "proc/sleep.h"
#include "proc/spinlock.h"
#include "proc/wait.h"
#include "sanitizers/tsan/tsan.h"
#include "sanitizers/tsan/tsan_access.h"
#include "test/kernel_tests.h"
#include "test/ktest.h"
#include "test/tsan/instrumented.h"

/*********************** Memory allocation helpers *************************/

// We use a special allocator that holds on to memory across tests then frees it
// all at the end.  If all tests are passing, this is unnecessary --- but if one
// test fails or misbehaves, then another test reuses the same memory, it can
// cause confusing results.
#define TSAN_TEST_MAX_ALLOCS 300
typedef struct {
  void* allocs[TSAN_TEST_MAX_ALLOCS];
  int next;
} tsan_test_allocs_t;
static tsan_test_allocs_t g_tsan_test_allocs;

static void* tsan_test_alloc(size_t n) {
  void* result = kmalloc(n);
  PUSH_AND_DISABLE_INTERRUPTS_NO_TSAN();
  g_tsan_test_allocs.allocs[g_tsan_test_allocs.next++] = result;
  POP_INTERRUPTS_NO_TSAN();
  return result;
}

static void tsan_test_free_all(void) {
  PUSH_AND_DISABLE_INTERRUPTS_NO_TSAN();
  for (int i = 0; i < g_tsan_test_allocs.next; ++i) {
    kfree(g_tsan_test_allocs.allocs[i]);
  }
  g_tsan_test_allocs.next = 0;
  POP_INTERRUPTS_NO_TSAN();
}

// Hook called at the end of each test that forces synchronization with
// interrupts and defints to ensure test hermeticity..  This could call
// tsan_test_free_all() to clean up memory and force reuse across tests (which
// could be an interesting stress test).
static void tsan_test_cleanup(void) {
  kspinlock_intsafe_t mu = KSPINLOCK_INTERRUPT_SAFE_INIT;
  kspin_lock_int(&mu);
  kspin_unlock_int(&mu);
  // tsan_test_free_all();
}

#define TS_MALLOC(_TYPE) ((_TYPE*)tsan_test_alloc(sizeof(_TYPE)));

/***************** Test report interception functions ******************/
static void test_report_fn(const tsan_report_t* report);

static bool g_found_report = false;
static tsan_report_t g_report;

// Start interception of TSAN reports for testing.
static void intercept_reports(void) {
  KEXPECT_FALSE(g_found_report);  // Safety check.
  tsan_set_report_func(&test_report_fn);
}

static void intercept_reports_done(void) {
  tsan_set_report_func(NULL);
  g_found_report = false;
}

static NO_TSAN void test_report_fn(const tsan_report_t* report) {
  PUSH_AND_DISABLE_INTERRUPTS();
  g_found_report = true;
  g_report = *report;
  POP_INTERRUPTS();
}

static bool type_matches(const char* s, tsan_access_type_t t) {
  if (kstrcmp(s, "?") == 0) {
    return true;
  } else if (kstrcmp(s, "r") == 0) {
    return (t == TSAN_ACCESS_READ);
  } else if (kstrcmp(s, "w") == 0) {
    return (t == TSAN_ACCESS_WRITE);
  } else {
    KEXPECT_STREQ("?", s);
    KTEST_ADD_FAILURE("Invalid type string");
    return false;
  }
}

// Expect that a particular report was found.
static bool expect_report(void* addr1, int size1, const char* type1,
                          bool has_stack1, void* addr2, int size2,
                          const char* type2, bool has_stack2, bool try_swap) {
  bool v = true;
  v &= KEXPECT_TRUE(g_found_report);
  if (!g_found_report) return v;

  // Try it swapped as well.
  if (try_swap && ((addr_t)addr1 != g_report.race.cur.addr ||
                   size1 != g_report.race.cur.size ||
                   !type_matches(type1, g_report.race.cur.type))) {
    return expect_report(addr2, size2, type2, has_stack2, addr1, size1, type1,
                         has_stack1, false);
  }

  v &= KEXPECT_EQ((addr_t)addr1, g_report.race.cur.addr);
  v &= KEXPECT_EQ(size1, g_report.race.cur.size);
  v &= type_matches(type1, g_report.race.cur.type);
  v &= KEXPECT_EQ((addr_t)addr2, g_report.race.prev.addr);
  v &= KEXPECT_EQ(size2, g_report.race.prev.size);
  v &= type_matches(type2, g_report.race.prev.type);

  // Crude stack trace checking.
  if (has_stack1) {
    v &= KEXPECT_NE(0, g_report.race.cur.trace[0]);
    v &= KEXPECT_NE(0, g_report.race.cur.trace[1]);
  } else {
    v &= KEXPECT_EQ(0, g_report.race.cur.trace[0]);
  }
  if (has_stack2) {
    v &= KEXPECT_NE(0, g_report.race.prev.trace[0]);
    v &= KEXPECT_NE(0, g_report.race.prev.trace[1]);
  } else {
    v &= KEXPECT_EQ(0, g_report.race.prev.trace[0]);
  }

  kmemset(&g_report, 0, sizeof(g_report));
  return v;
}

#define EXPECT_REPORT(addr1, size1, type1, addr2, size2, type2)              \
  KEXPECT_TRUE(expect_report(addr1, size1, type1, true, addr2, size2, type2, \
                             true, true))

#define EXPECT_REPORT_NO_STACK(addr1, size1, type1, addr2, size2, type2)     \
  KEXPECT_TRUE(expect_report(addr1, size1, type1, true, addr2, size2, type2, \
                             false, true))

// Helper to wait until races occur, ensuring that tests don't reap threads
// before the races occur (which causes spurious test failures due to missing
// stack traces).
static bool wait_for_race(void) {
  PUSH_AND_DISABLE_INTERRUPTS_NO_TSAN();
  for (int i = 0; i < 10; ++i) {
    if (g_found_report) break;
    ksleep(10);
  }
  bool result = g_found_report;
  POP_INTERRUPTS_NO_TSAN();
  return result;
}

/************************** Tests ************************************/
typedef struct {
  kmutex_t mu;
  kspinlock_t spin;
  kspinlock_intsafe_t spin_int;
  uint64_t* val;
} mutex_test_args_t;

static void tsan_basic_sanity_test(void) {
  KTEST_BEGIN("TSAN: basic R/W heap value instrumentation");
  int* x = TS_MALLOC(int);
  *x = 0;
  tsan_rw_value(x);
  KEXPECT_EQ(1, *x);
  tsan_rw_value(x);
  KEXPECT_EQ(2, *x);
  tsan_rw_value(x);
  KEXPECT_EQ(3, *x);
  tsan_test_cleanup();
}

static void* rw_value_thread(void* arg) {
  int* x = (int*)arg;
  tsan_rw_value(x);
  tsan_rw_value(x);
  return NULL;
}

static void* rw_value_thread_preempt(void* arg) {
  sched_enable_preemption_for_test();
  int* x = (int*)arg;
  tsan_rw_value(x);
  ksleep(30);
  return NULL;
}

static void tsan_basic_sanity_test2(void) {
  KTEST_BEGIN("TSAN: basic R/W heap value instrumentation (two threads)");
  int* x = TS_MALLOC(int);
  *x = 0;
  tsan_rw_value(x);

  // When both are non-preemptible, no race should be detected (for now).
  kthread_t thread;
  KEXPECT_EQ(0, proc_thread_create(&thread, &rw_value_thread, x));
  ksleep(20);
  tsan_rw_value(x);
  tsan_rw_value(x);
  KEXPECT_EQ(NULL, kthread_join(thread));
  KEXPECT_EQ(5, *x);

  // When the other thread is preemptible, it should trigger a race.  Need some
  // funny sleeps to ensure the other thread starts first and runs (to avoid the
  // special implicit sync point at the start of each thread).
  *x = 0;
  intercept_reports();
  tsan_rw_value(x);
  KEXPECT_EQ(0, proc_thread_create(&thread, &rw_value_thread_preempt, x));
  ksleep(20);
  tsan_rw_value(x);
  EXPECT_REPORT(x, 4, "w", x, 4, "?");

  KEXPECT_EQ(NULL, kthread_join(thread));
  intercept_reports_done();

  tsan_test_cleanup();
}

static void* rw_value_thread_kmutex(void* arg) {
  mutex_test_args_t* args = (mutex_test_args_t*)arg;

  // Non-racing accesses.  Should be OK.
  tsan_rw_u64(&args->val[1]);
  tsan_rw_u64(&args->val[3]);

  kmutex_lock(&args->mu);
  tsan_rw_u64(args->val);
  kmutex_unlock(&args->mu);
  kmutex_lock(&args->mu);
  tsan_rw_u64(args->val);
  kmutex_unlock(&args->mu);
  return NULL;
}

static void tsan_basic_sanity_test3(void) {
  KTEST_BEGIN("TSAN: basic R/W heap value (two threads, locked)");
  mutex_test_args_t args;
  kmutex_init(&args.mu);
  args.val = tsan_test_alloc(sizeof(uint64_t) * 4);
  for (int i = 0; i < 4; ++i) {
    args.val[i] = 0;
    tsan_rw_u64(args.val + i);
  }
  kthread_t thread;
  KEXPECT_EQ(0, proc_thread_create(&thread, &rw_value_thread_kmutex, &args));
  // Non-racing access.
  tsan_rw_u64(&args.val[2]);

  kmutex_lock(&args.mu);
  tsan_rw_u64(args.val);
  kmutex_unlock(&args.mu);
  kmutex_lock(&args.mu);
  tsan_rw_u64(args.val);
  kmutex_unlock(&args.mu);

  KEXPECT_EQ(NULL, kthread_join(thread));
  // A join should act as a synchronization point between the threads.
  tsan_rw_u64(args.val);

  KEXPECT_EQ(6, args.val[0]);
  KEXPECT_EQ(2, args.val[1]);
  KEXPECT_EQ(2, args.val[2]);
  KEXPECT_EQ(2, args.val[3]);
  tsan_test_cleanup();
}

static void* rw_value_thread_kspinlock(void* arg) {
  KASSERT(kthread_current_thread()->preemption_disables == 0);

  mutex_test_args_t* args = (mutex_test_args_t*)arg;

  // Non-racing accesses.  Should be OK.
  tsan_rw_u64(&args->val[1]);
  tsan_rw_u64(&args->val[3]);

  kspin_lock(&args->spin);
  tsan_rw_u64(args->val);
  kspin_unlock(&args->spin);

  kspin_lock(&args->spin);
  tsan_rw_u64(args->val);
  kspin_unlock(&args->spin);
  return NULL;
}

static void tsan_basic_sanity_test3_spinlock(void) {
  KTEST_BEGIN("TSAN: basic R/W heap value (two threads, spin-locked)");
  mutex_test_args_t args;
  args.spin = KSPINLOCK_NORMAL_INIT;
  args.val = tsan_test_alloc(sizeof(uint64_t) * 4);
  for (int i = 0; i < 4; ++i) {
    args.val[i] = 0;
    tsan_rw_u64(args.val + i);
  }
  kthread_t thread;
  sched_enable_preemption_for_test();
  KEXPECT_EQ(0, proc_thread_create(&thread, &rw_value_thread_kspinlock, &args));
  // Non-racing access.
  tsan_rw_u64(&args.val[2]);

  kspin_lock(&args.spin);
  tsan_rw_u64(args.val);
  kspin_unlock(&args.spin);

  kspin_lock(&args.spin);
  tsan_rw_u64(args.val);
  kspin_unlock(&args.spin);

  KEXPECT_EQ(NULL, kthread_join(thread));
  // A join should act as a synchronization point between the threads.
  tsan_rw_u64(args.val);

  sched_disable_preemption();

  KEXPECT_EQ(6, args.val[0]);
  KEXPECT_EQ(2, args.val[1]);
  KEXPECT_EQ(2, args.val[2]);
  KEXPECT_EQ(2, args.val[3]);
  tsan_test_cleanup();
}

static void* rw_value_thread_kspinlock_int(void* arg) {
  KASSERT(kthread_current_thread()->preemption_disables == 0);

  mutex_test_args_t* args = (mutex_test_args_t*)arg;

  // Non-racing accesses.  Should be OK.
  tsan_rw_u64(&args->val[1]);
  tsan_rw_u64(&args->val[3]);

  kspin_lock_int(&args->spin_int);
  tsan_rw_u64(args->val);
  kspin_unlock_int(&args->spin_int);

  kspin_lock_int(&args->spin_int);
  tsan_rw_u64(args->val);
  kspin_unlock_int(&args->spin_int);
  return NULL;
}

static void tsan_basic_sanity_test3_spinlock_intsafe(void) {
  KTEST_BEGIN("TSAN: basic R/W heap value (two threads, intsafe-spin-locked)");
  mutex_test_args_t args;
  args.spin_int = KSPINLOCK_INTERRUPT_SAFE_INIT;
  args.val = tsan_test_alloc(sizeof(uint64_t) * 4);
  for (int i = 0; i < 4; ++i) {
    args.val[i] = 0;
    tsan_rw_u64(args.val + i);
  }
  kthread_t thread;
  sched_enable_preemption_for_test();
  KEXPECT_EQ(
      0, proc_thread_create(&thread, &rw_value_thread_kspinlock_int, &args));
  // Non-racing access.
  tsan_rw_u64(&args.val[2]);

  kspin_lock_int(&args.spin_int);
  tsan_rw_u64(args.val);
  kspin_unlock_int(&args.spin_int);

  kspin_lock_int(&args.spin_int);
  tsan_rw_u64(args.val);
  kspin_unlock_int(&args.spin_int);

  KEXPECT_EQ(NULL, kthread_join(thread));
  // A join should act as a synchronization point between the threads.
  tsan_rw_u64(args.val);

  sched_disable_preemption();

  KEXPECT_EQ(6, args.val[0]);
  KEXPECT_EQ(2, args.val[1]);
  KEXPECT_EQ(2, args.val[2]);
  KEXPECT_EQ(2, args.val[3]);
  tsan_test_cleanup();
}

// As above, but sleep after thread creation to test passing values without
// locking to a new thread (which should be allowed).
static void tsan_basic_sanity_test4(void) {
  KTEST_BEGIN("TSAN: basic R/W heap value (two threads, locked, sleep)");
  mutex_test_args_t args;
  kmutex_init(&args.mu);
  args.val = tsan_test_alloc(sizeof(uint64_t) * 4);
  for (int i = 0; i < 4; ++i) {
    args.val[i] = 0;
    tsan_rw_u64(args.val + i);
  }
  kthread_t thread;
  KEXPECT_EQ(0, proc_thread_create(&thread, &rw_value_thread_kmutex, &args));
  ksleep(10);

  kmutex_lock(&args.mu);
  tsan_rw_u64(args.val);
  kmutex_unlock(&args.mu);

  KEXPECT_EQ(NULL, kthread_join(thread));
  // A join should act as a synchronization point between the threads.
  tsan_rw_u64(args.val);

  KEXPECT_EQ(5, args.val[0]);
  KEXPECT_EQ(2, args.val[1]);
  tsan_test_cleanup();
}

static void* size1_thread(void* arg) {
  // Assume that the given pointer is already offset correctly, and just read it
  // 8 times with a stride of 8 bytes.
  uint8_t* ptr = (uint8_t*)arg;
  uint8_t val;
  for (int i = 0; i < 8; ++i) {
    uint8_t new_val = tsan_read8(ptr);
    if (i == 0) {
      val = new_val;
    } else {
      KEXPECT_EQ(val, new_val);
    }
    ptr += 8;
  }
  return (void*)(intptr_t)val;
}

// Test independence of each byte within a memory cell.  Concurrent Reads and
// writes to two different bytes within a uint64_t (one TSAN memory cell) should
// be OK.
static void size1_safe_test(void) {
  KTEST_BEGIN("TSAN: two threads accessing different 1 bytes is safe");
  uint64_t* vals = tsan_test_alloc(sizeof(uint64_t) * 8);
  uint64_t orig = htob64(0x0123456789abcdefll);

  for (int byte_pos_to_test = 0; byte_pos_to_test < 8; ++byte_pos_to_test) {
    for (int i = 0; i < 8; ++i) {
      vals[i] = orig;
    }
    // For each byte position to test, have the other thread read that byte
    // position in all 8 of the test dwords.  This thread will write a different
    // "second" byte position in each of the test dwords --- none should
    // conflict.
    uint8_t* val8 = (uint8_t*)vals;
    kthread_t thread;
    KEXPECT_EQ(
        0, proc_thread_create(&thread, &size1_thread, val8 + byte_pos_to_test));
    for (int i = 0; i < 8; ++i) {
      if (i == byte_pos_to_test) continue;
      tsan_write8(&val8[i * 8 + i], 0x00);
    }
    KEXPECT_EQ(((uint8_t*)&orig)[byte_pos_to_test],
               (intptr_t)kthread_join(thread));
  }
  tsan_test_cleanup();
}

// As above, but use kmemset() instead of a direct write.
static void size1_memset_safe_test(void) {
  KTEST_BEGIN("TSAN: two threads accessing different 1 bytes is safe (memset)");
  uint64_t* vals = tsan_test_alloc(sizeof(uint64_t) * 8);
  uint64_t orig = htob64(0x0123456789abcdefll);

  for (int byte_pos_to_test = 0; byte_pos_to_test < 8; ++byte_pos_to_test) {
    for (int i = 0; i < 8; ++i) {
      vals[i] = orig;
    }
    // For each byte position to test, have the other thread read that byte
    // position in all 8 of the test dwords.  This thread will write a different
    // "second" byte position in each of the test dwords --- none should
    // conflict.
    uint8_t* val8 = (uint8_t*)vals;
    kthread_t thread;
    KEXPECT_EQ(
        0, proc_thread_create(&thread, &size1_thread, val8 + byte_pos_to_test));
    for (int i = 0; i < 8; ++i) {
      if (i == byte_pos_to_test) continue;
      kmemset(&val8[i * 8 + i], 0x00, 1);
    }
    KEXPECT_EQ(((uint8_t*)&orig)[byte_pos_to_test],
               (intptr_t)kthread_join(thread));
  }
  tsan_test_cleanup();
}

static void size1_memcpy_safe_test(void) {
  KTEST_BEGIN("TSAN: two threads accessing different 1 bytes is safe (memcpy)");
  uint64_t* vals = tsan_test_alloc(sizeof(uint64_t) * 8);
  uint64_t orig = htob64(0x0123456789abcdefll);

  for (int byte_pos_to_test = 0; byte_pos_to_test < 8; ++byte_pos_to_test) {
    for (int i = 0; i < 8; ++i) {
      vals[i] = orig;
    }
    // For each byte position to test, have the other thread read that byte
    // position in all 8 of the test dwords.  This thread will write a different
    // "second" byte position in each of the test dwords --- none should
    // conflict.
    uint8_t* val8 = (uint8_t*)vals;
    kthread_t thread;
    KEXPECT_EQ(
        0, proc_thread_create(&thread, &size1_thread, val8 + byte_pos_to_test));
    for (int i = 0; i < 8; ++i) {
      if (i == byte_pos_to_test) continue;
      char c = 0;
      kmemcpy(&val8[i * 8 + i], &c, 1);
    }
    KEXPECT_EQ(((uint8_t*)&orig)[byte_pos_to_test],
               (intptr_t)kthread_join(thread));
  }
  tsan_test_cleanup();
}

// As above, but with concurrent 1-byte/2-byte accesses.
static void size2_safe_test(void) {
  KTEST_BEGIN("TSAN: two threads accessing different 2 bytes is safe");
  uint64_t* vals = tsan_test_alloc(sizeof(uint64_t) * 8);
  uint64_t orig = htob64(0x0123456789abcdefll);

  for (int byte_pos_to_test = 0; byte_pos_to_test < 8; ++byte_pos_to_test) {
    for (int i = 0; i < 8; ++i) {
      vals[i] = orig;
    }
    uint8_t* val8 = (uint8_t*)vals;
    kthread_t thread;
    KEXPECT_EQ(
        0, proc_thread_create(&thread, &size1_thread, val8 + byte_pos_to_test));
    for (int i = 0; i < 7; ++i) {
      if (byte_pos_to_test >= i && byte_pos_to_test < i + 2) continue;
      if (i % 2 == 0) {
        tsan_write16((uint16_t*)&val8[i * 8 + i], 0x00);
      } else {
        KEXPECT_NE(0, tsan_unaligned_read16((uint16_t*)&val8[i * 8 + i]));
        tsan_unaligned_write16((uint16_t*)&val8[i * 8 + i], 0x00);
      }
    }
    KEXPECT_EQ(((uint8_t*)&orig)[byte_pos_to_test],
               (intptr_t)kthread_join(thread));
  }
  tsan_test_cleanup();
}

// As above, but with concurrent 1-byte/4-byte accesses.
static void size4_safe_test(void) {
  KTEST_BEGIN("TSAN: two threads accessing different 4 bytes is safe");
  uint64_t* vals = tsan_test_alloc(sizeof(uint64_t) * 8);
  uint64_t orig = htob64(0x0123456789abcdefll);

  for (int byte_pos_to_test = 0; byte_pos_to_test < 8; ++byte_pos_to_test) {
    for (int i = 0; i < 8; ++i) {
      vals[i] = orig;
    }
    uint8_t* val8 = (uint8_t*)vals;
    kthread_t thread;
    KEXPECT_EQ(
        0, proc_thread_create(&thread, &size1_thread, val8 + byte_pos_to_test));
    for (int i = 0; i < 5; ++i) {
      if (byte_pos_to_test >= i && byte_pos_to_test < i + 4) continue;
      if (i % 4 == 0) {
        tsan_write32((uint32_t*)&val8[i * 8 + i], 0x00);
      } else {
        KEXPECT_NE(0, tsan_unaligned_read32((uint32_t*)&val8[i * 8 + i]));
        tsan_unaligned_write32((uint32_t*)&val8[i * 8 + i], 0x00);
      }
    }
    KEXPECT_EQ(((uint8_t*)&orig)[byte_pos_to_test],
               (intptr_t)kthread_join(thread));
  }
  tsan_test_cleanup();
}

typedef struct {
  uint64_t* val;
  kthread_queue_t q;
} write_and_wake_test_args_t;

static void* write_and_wake_one(void* arg) {
  write_and_wake_test_args_t* args = (write_and_wake_test_args_t*)arg;
  tsan_rw_u64(args->val);
  scheduler_wake_one(&args->q);
  return NULL;
}

static void* write_and_wake_all(void* arg) {
  write_and_wake_test_args_t* args = (write_and_wake_test_args_t*)arg;
  tsan_rw_u64(args->val);
  scheduler_wake_all(&args->q);
  return NULL;
}

// Test the standard pattern in non-preemptible code of using a thread wait
// queue to synchronize between threads.
// TODO(SMP): remove this when this pattern is no longer used.
static void tsan_wait_queue_test(void) {
  KTEST_BEGIN("TSAN: synchronization with kthread_queue_t");
  uint64_t* val = TS_MALLOC(uint64_t);
  tsan_write64(val, 5);
  write_and_wake_test_args_t args;
  args.val = val;
  kthread_queue_init(&args.q);

  // Test scheduler_wake_one().
  kthread_t child;
  KEXPECT_EQ(0, proc_thread_create(&child, write_and_wake_one, &args));

  tsan_rw_u64(args.val);
  KEXPECT_EQ(SWAIT_DONE, scheduler_wait_on_interruptable(&args.q, 1000));
  tsan_rw_u64(args.val);

  KEXPECT_EQ(8, *args.val);
  KEXPECT_EQ(NULL, kthread_join(child));

  // Test scheduler_wake_all().
  KEXPECT_EQ(0, proc_thread_create(&child, write_and_wake_all, &args));

  tsan_rw_u64(args.val);
  KEXPECT_EQ(SWAIT_DONE, scheduler_wait_on_interruptable(&args.q, 1000));
  tsan_rw_u64(args.val);

  KEXPECT_EQ(11, *args.val);
  KEXPECT_EQ(NULL, kthread_join(child));
  tsan_test_cleanup();
}

static void* fork_test_child_thread(void* arg) {
  tsan_rw_u64((uint64_t*)arg);
  return NULL;
}

static void fork_test_child(void* arg) {
  uint64_t* vals = (uint64_t*)arg;
  kthread_t child1, child2;
  KEXPECT_EQ(0, proc_thread_create(&child1, &fork_test_child_thread, &vals[1]));
  KEXPECT_EQ(0, proc_thread_create(&child2, &fork_test_child_thread, &vals[2]));
  kthread_detach(child1);
  kthread_join(child2);
  tsan_rw_u64(&vals[0]);
}

// Test that forks multiple processes, who each also create detached threads.
// Waiting on the process to exit should be sufficient to synchronize.
static void tsan_fork_test(void) {
  KTEST_BEGIN("TSAN: synchronization across process fork/wait");
  // For each child proc, three values:
  // 1) for main thread
  // 2) for an explicitly detached thread
  // 3) for a joined thread
  uint64_t* vals = tsan_test_alloc(sizeof(uint64_t) * 6);
  tsan_write64(&vals[0], 5);
  tsan_write64(&vals[1], 6);
  tsan_write64(&vals[2], 7);
  tsan_write64(&vals[3], 8);
  tsan_write64(&vals[4], 9);
  tsan_write64(&vals[5], 10);

  kpid_t child1 = proc_fork(fork_test_child, vals);
  KEXPECT_GE(child1, 0);
  kpid_t child2 = proc_fork(fork_test_child, vals + 3);
  KEXPECT_GE(child2, 0);

  KEXPECT_EQ(child1, proc_waitpid(child1, NULL, 0));
  KEXPECT_EQ(child2, proc_waitpid(child2, NULL, 0));

  KEXPECT_EQ(6, tsan_read64(&vals[0]));
  KEXPECT_EQ(7, tsan_read64(&vals[1]));
  KEXPECT_EQ(8, tsan_read64(&vals[2]));
  KEXPECT_EQ(9, tsan_read64(&vals[3]));
  KEXPECT_EQ(10, tsan_read64(&vals[4]));
  KEXPECT_EQ(11, tsan_read64(&vals[5]));
  tsan_test_cleanup();
}

static void* access_u8(void* arg) {
  // In each of these threads, we need to enable preemption, then briefly sleep.
  // This allows the other thread(s) to start and do the same, ensuring they are
  // all non-synchronized with each other.
  sched_enable_preemption_for_test();
  ksleep(10);
  tsan_write8((uint8_t*)arg, 1);
  sched_disable_preemption();
  return NULL;
}

static void* read_u8(void* arg) {
  sched_enable_preemption_for_test();
  ksleep(10);
  tsan_read8((uint8_t*)arg);
  sched_disable_preemption();
  return NULL;
}

static void* access_u16(void* arg) {
  sched_enable_preemption_for_test();
  ksleep(10);
  tsan_unaligned_write16((uint16_t*)arg, htob16(0xabcd));
  sched_disable_preemption();
  return NULL;
}

static void* access_u32(void* arg) {
  sched_enable_preemption_for_test();
  ksleep(10);
  tsan_unaligned_write32((uint32_t*)arg, htob32(0xabcd1234));
  sched_disable_preemption();
  return NULL;
}

static void* access_u64(void* arg) {
  sched_enable_preemption_for_test();
  ksleep(10);
  tsan_unaligned_write64((uint64_t*)arg, 0xabababababababab);
  sched_disable_preemption();
  return NULL;
}

static void* access_memset_15bytes(void* arg) {
  sched_enable_preemption_for_test();
  ksleep(10);
  tsan_test_kmemset(arg, 0x12, 15);
  sched_disable_preemption();
  return NULL;
}

static void* access_memset_16bytes(void* arg) {
  sched_enable_preemption_for_test();
  ksleep(10);
  tsan_test_kmemset(arg, 0x12, 16);
  sched_disable_preemption();
  return NULL;
}

static void* access_implicit_memset(void* arg) {
  sched_enable_preemption_for_test();
  ksleep(10);
  tsan_implicit_memset((tsan_test_struct_t*)arg);
  sched_disable_preemption();
  return NULL;
}

typedef struct {
  void* dst;
  const void* src;
  size_t n;
} access_memcpy_args_t;

static void* access_memcpy(void* arg) {
  sched_enable_preemption_for_test();
  ksleep(10);
  access_memcpy_args_t* args = (access_memcpy_args_t*)arg;
  tsan_test_kmemcpy(args->dst, args->src, args->n);
  sched_disable_preemption();
  return NULL;
}

static void* access_implicit_memcpy(void* arg) {
  sched_enable_preemption_for_test();
  ksleep(10);
  tsan_implicit_memcpy((tsan_test_struct_t*)arg);
  sched_disable_preemption();
  return NULL;
}

static void unaligned_overlap_2byte_test(void) {
  KTEST_BEGIN("TSAN: unaligned 2-byte access that straddles two shadow cells");
  uint64_t* vals = tsan_test_alloc(sizeof(uint64_t) * 2);
  uint8_t* vals8 = (uint8_t*)vals;
  tsan_write64(vals, 0);
  tsan_write64(vals + 1, 0);

  // Access the two bytes on either side of the straddled uint16_t.
  kthread_t threads[3];
  KEXPECT_EQ(0, proc_thread_create(&threads[0], &access_u8, &vals8[6]));
  KEXPECT_EQ(0, proc_thread_create(&threads[1], &access_u8, &vals8[9]));

  // ...and then access the straddled uint16_t.
  KEXPECT_EQ(0, proc_thread_create(&threads[2], &access_u16, &vals8[7]));

  KEXPECT_EQ(NULL, kthread_join(threads[0]));
  KEXPECT_EQ(NULL, kthread_join(threads[1]));
  KEXPECT_EQ(NULL, kthread_join(threads[2]));

  KEXPECT_EQ(0x01, vals8[6]);
  KEXPECT_EQ(0xab, vals8[7]);
  KEXPECT_EQ(0xcd, vals8[8]);
  KEXPECT_EQ(0x01, vals8[9]);
  tsan_test_cleanup();
}

static void unaligned_overlap_2byte_conflict_test(void) {
  KTEST_BEGIN(
      "TSAN: unaligned 2-byte access that straddles two shadow cells "
      "(conflict)");
  uint64_t* vals = tsan_test_alloc(sizeof(uint64_t) * 2);
  uint8_t* vals8 = (uint8_t*)vals;
  tsan_write64(vals, 0);
  tsan_write64(vals + 1, 0);

  // First test: access the first byte of the straddled uint16_t (last byte of
  // the first shadow cell).
  kthread_t threads[2];
  intercept_reports();
  KEXPECT_EQ(0, proc_thread_create(&threads[0], &access_u8, &vals8[7]));

  // ...and then access the straddled uint16_t.
  KEXPECT_EQ(0, proc_thread_create(&threads[1], &access_u16, &vals8[7]));

  KEXPECT_EQ(NULL, kthread_join(threads[0]));
  KEXPECT_EQ(NULL, kthread_join(threads[1]));

  // We should have gotten a conflict.
  EXPECT_REPORT(&vals8[7], 1, "w", &vals8[7], 2, "w");
  intercept_reports_done();


  // Second test: access the second byte of the straddled uint16_t (first byte
  // of the second shadow cell).
  intercept_reports();
  KEXPECT_EQ(0, proc_thread_create(&threads[0], &access_u8, &vals8[8]));

  // ...and then access the straddled uint16_t.
  KEXPECT_EQ(0, proc_thread_create(&threads[1], &access_u16, &vals8[7]));

  KEXPECT_TRUE(wait_for_race());
  KEXPECT_EQ(NULL, kthread_join(threads[0]));
  KEXPECT_EQ(NULL, kthread_join(threads[1]));

  // We should have gotten a conflict.
  EXPECT_REPORT(&vals8[8], 1, "w", &vals8[7], 2, "w");
  intercept_reports_done();
  tsan_test_cleanup();
}

static void unaligned_overlap_4byte_test(void) {
  KTEST_BEGIN("TSAN: unaligned 4-byte access that straddles two shadow cells");
  uint64_t* vals = tsan_test_alloc(sizeof(uint64_t) * 2);
  uint8_t* vals8 = (uint8_t*)vals;

  for (int i = 0; i < 3; ++i) {
    tsan_write64(vals, 0);
    tsan_write64(vals + 1, 0);

    // Access the two bytes on either side of the straddled uint32_t.
    kthread_t threads[3];
    KEXPECT_EQ(0, proc_thread_create(&threads[0], &access_u8, &vals8[4 + i]));
    KEXPECT_EQ(0, proc_thread_create(&threads[1], &access_u8, &vals8[9 + i]));

    // ...and then access the straddled uint32_t.
    KEXPECT_EQ(0, proc_thread_create(&threads[2], &access_u32, &vals8[5 + i]));

    KEXPECT_EQ(NULL, kthread_join(threads[0]));
    KEXPECT_EQ(NULL, kthread_join(threads[1]));
    KEXPECT_EQ(NULL, kthread_join(threads[2]));

    KEXPECT_EQ(0x01, vals8[4 + i]);
    KEXPECT_EQ(0xab, vals8[5 + i]);
    KEXPECT_EQ(0xcd, vals8[6 + i]);
    KEXPECT_EQ(0x12, vals8[7 + i]);
    KEXPECT_EQ(0x34, vals8[8 + i]);
    KEXPECT_EQ(0x01, vals8[9 + i]);
  }
  tsan_test_cleanup();
}

static void unaligned_overlap_4byte_conflict_test(void) {
  KTEST_BEGIN(
      "TSAN: unaligned 4-byte access that straddles two shadow cells "
      "(conflict)");
  uint64_t* vals = tsan_test_alloc(sizeof(uint64_t) * 2);
  uint8_t* vals8 = (uint8_t*)vals;

  for (int i = 0; i < 4; ++i) {
    tsan_write64(vals, 0);
    tsan_write64(vals + 1, 0);

    kthread_t threads[2];
    intercept_reports();
    KEXPECT_EQ(0, proc_thread_create(&threads[0], &access_u8, &vals8[5 + i]));

    // ...and then access the straddled uint32_t.
    KEXPECT_EQ(0, proc_thread_create(&threads[1], &access_u32, &vals8[5]));

    KEXPECT_TRUE(wait_for_race());
    KEXPECT_EQ(NULL, kthread_join(threads[0]));
    KEXPECT_EQ(NULL, kthread_join(threads[1]));

    // We should have gotten a conflict.
    EXPECT_REPORT(&vals8[5 + i], 1, "w", &vals8[5], 4, "w");
    intercept_reports_done();
  }
  tsan_test_cleanup();
}

static void unaligned_overlap_8byte_test(void) {
  KTEST_BEGIN("TSAN: unaligned 8-byte access that straddles two shadow cells");
  uint64_t* vals = tsan_test_alloc(sizeof(uint64_t) * 2);
  uint8_t* vals8 = (uint8_t*)vals;

  for (int i = 0; i < 7; ++i) {
    tsan_write64(vals, 0);
    tsan_write64(vals + 1, 0);

    // Access the two bytes on either side of the straddled uint64_t.
    kthread_t threads[3];
    KEXPECT_EQ(0, proc_thread_create(&threads[0], &access_u8, &vals8[i]));
    KEXPECT_EQ(0, proc_thread_create(&threads[1], &access_u8, &vals8[9 + i]));

    // ...and then access the straddled uint64_t.
    KEXPECT_EQ(0, proc_thread_create(&threads[2], &access_u64, &vals8[1 + i]));

    KEXPECT_EQ(NULL, kthread_join(threads[0]));
    KEXPECT_EQ(NULL, kthread_join(threads[1]));
    KEXPECT_EQ(NULL, kthread_join(threads[2]));

    KEXPECT_EQ(0x01, vals8[i]);
    KEXPECT_EQ(0xab, vals8[1 + i]);
    KEXPECT_EQ(0xab, vals8[2 + i]);
    KEXPECT_EQ(0xab, vals8[3 + i]);
    KEXPECT_EQ(0xab, vals8[4 + i]);
    KEXPECT_EQ(0xab, vals8[5 + i]);
    KEXPECT_EQ(0xab, vals8[6 + i]);
    KEXPECT_EQ(0xab, vals8[7 + i]);
    KEXPECT_EQ(0xab, vals8[8 + i]);
    KEXPECT_EQ(0x01, vals8[9 + i]);
  }
  tsan_test_cleanup();
}

static void unaligned_overlap_8byte_conflict_test(void) {
  KTEST_BEGIN(
      "TSAN: unaligned 8-byte access that straddles two shadow cells "
      "(conflict)");
  uint64_t* vals = tsan_test_alloc(sizeof(uint64_t) * 2);
  uint8_t* vals8 = (uint8_t*)vals;

  for (int i = 0; i < 8; ++i) {
    tsan_write64(vals, 0);
    tsan_write64(vals + 1, 0);

    kthread_t threads[2];
    intercept_reports();
    KEXPECT_EQ(0, proc_thread_create(&threads[0], &access_u8, &vals8[1 + i]));

    // ...and then access the straddled uint32_t.
    KEXPECT_EQ(0, proc_thread_create(&threads[1], &access_u64, &vals8[1]));

    KEXPECT_TRUE(wait_for_race());
    KEXPECT_EQ(NULL, kthread_join(threads[0]));
    KEXPECT_EQ(NULL, kthread_join(threads[1]));

    // We should have gotten a conflict.
    EXPECT_REPORT(&vals8[1 + i], 1, "w", &vals8[1], 8, "w");
    intercept_reports_done();
  }
  tsan_test_cleanup();
}

static void basic_tests(void) {
  tsan_basic_sanity_test();
  tsan_basic_sanity_test2();
  tsan_basic_sanity_test3();
  tsan_basic_sanity_test3_spinlock();
  tsan_basic_sanity_test3_spinlock_intsafe();
  tsan_basic_sanity_test4();
  size1_safe_test();
  size1_memset_safe_test();
  size1_memcpy_safe_test();
  size2_safe_test();
  size4_safe_test();
  tsan_wait_queue_test();
  tsan_fork_test();

  unaligned_overlap_2byte_test();
  unaligned_overlap_2byte_conflict_test();

  unaligned_overlap_4byte_test();
  unaligned_overlap_4byte_conflict_test();

  unaligned_overlap_8byte_test();
  unaligned_overlap_8byte_conflict_test();
}

static void interrupt_fn(void* arg) {
  KASSERT(kthread_execution_context() == KTCTX_INTERRUPT);
  int* x = (int*)arg;
  tsan_rw_value(x);
}

static void busy_loop(void) { for (volatile int i = 0; i < 10000000; ++i); }
static void* busy_loop_thread(void* arg) {
  for (volatile int i = 0; i < 10000000; ++i);
  return NULL;
}

static void interrupt_test1(void) {
  KTEST_BEGIN("TSAN: interrupt-safety");
  int* x = TS_MALLOC(int);
  *x = 0;
  tsan_rw_value(x);

  {
    PUSH_AND_DISABLE_INTERRUPTS();
    register_event_timer(get_time_ms() + 10, &interrupt_fn, x, NULL);
    busy_loop();
    POP_INTERRUPTS();
    ksleep(10);
    tsan_rw_value(x);
    KEXPECT_EQ(3, *x);
  }
  tsan_test_cleanup();
}

static void interrupt_test1b(void) {
  KTEST_BEGIN("TSAN: interrupt-safety (with kspinlock_int)");
  int* x = TS_MALLOC(int);
  *x = 0;
  tsan_rw_value(x);

  kspinlock_intsafe_t mu = KSPINLOCK_INTERRUPT_SAFE_INIT;
  {
    kspin_lock_int(&mu);
    register_event_timer(get_time_ms() + 10, &interrupt_fn, x, NULL);
    busy_loop();
    kspin_unlock_int(&mu);
    ksleep(10);
    tsan_rw_value(x);
    KEXPECT_EQ(3, *x);
  }
  tsan_test_cleanup();
}

static void interrupt_test1c(void) {
  KTEST_BEGIN("TSAN: interrupt-safety (with scheduler_wait_on() timeout)");
  int* x = TS_MALLOC(int);
  *x = 0;
  tsan_rw_value(x);

  kthread_queue_t q;
  kthread_queue_init(&q);
  KEXPECT_EQ(SWAIT_TIMEOUT, scheduler_wait_on_interruptable(&q, 20));
  tsan_test_cleanup();
}

// As above, but with interrupts disabled (so that POP_INTERRUPTS() calls in
// scheduler_wait_on_interruptable() don't do anything).
static void interrupt_test1d(void) {
  KTEST_BEGIN("TSAN: interrupt-safety (with scheduler_wait_on() timeout #2)");
  int* x = TS_MALLOC(int);
  *x = 0;
  tsan_rw_value(x);

  kthread_queue_t q;
  kthread_queue_init(&q);
  PUSH_AND_DISABLE_INTERRUPTS();
  KEXPECT_EQ(SWAIT_TIMEOUT, scheduler_wait_on_interruptable(&q, 20));
  POP_INTERRUPTS();
  tsan_test_cleanup();
}

// As above, but also with an unsynchronized thread that can run while we're
// waiting.
static void interrupt_test1e(void) {
  KTEST_BEGIN("TSAN: interrupt-safety (with scheduler_wait_on() timeout #3)");
  int* x = TS_MALLOC(int);
  *x = 0;
  tsan_rw_value(x);

  kthread_t thread;
  KEXPECT_EQ(0, kthread_create(&thread, busy_loop_thread, NULL));
  scheduler_make_runnable(thread);

  kthread_queue_t q;
  kthread_queue_init(&q);
  PUSH_AND_DISABLE_INTERRUPTS();
  KEXPECT_EQ(SWAIT_TIMEOUT, scheduler_wait_on_interruptable(&q, 20));
  POP_INTERRUPTS();

  kthread_join(thread);
  tsan_test_cleanup();
}

static void interrupt_test2(void) {
  KTEST_BEGIN("TSAN: interrupt-safety (conflict)");
  int* x = TS_MALLOC(int);
  *x = 0;

  intercept_reports();
  tsan_rw_value(x);

  register_event_timer(get_time_ms() + 10, &interrupt_fn, x, NULL);
  busy_loop();
  tsan_rw_value(x);
  EXPECT_REPORT(x, 4, "r", x, 4, "w");
  intercept_reports_done();
  KEXPECT_EQ(3, *x);

  tsan_test_cleanup();
}

// Slight variant on the above where we write to the value _after_ we schedule
// the interrupt.
static void interrupt_test3(void) {
  KTEST_BEGIN("TSAN: interrupt-safety (conflict #2)");
  int* x = TS_MALLOC(int);
  *x = 0;

  intercept_reports();

  register_event_timer(get_time_ms() + 10, &interrupt_fn, x, NULL);
  tsan_rw_value(x);
  // The interrupt probably runs here and races with the above line.  There is a
  // small chance it runs first, though (in which case this collapses down to
  // the same as interrupt_test2() above).
  busy_loop();
  EXPECT_REPORT(x, 4, "?", x, 4, "w");
  intercept_reports_done();
  KEXPECT_EQ(2, *x);

  tsan_test_cleanup();
}

// Combo test where thread 1 races with thread 2 by sleeping in an
// interrupt-disabled critical section (which, FWIW, is incorrect).
static void interrupt_test4(void) {
  KTEST_BEGIN("TSAN: interrupt-safety (conflict #2)");
  int* x = TS_MALLOC(int);
  *x = 0;

  intercept_reports();

  register_event_timer(get_time_ms() + 10, &interrupt_fn, x, NULL);
  tsan_rw_value(x);
  // The interrupt probably runs here and races with the above line.  There is a
  // small chance it runs first, though (in which case this collapses down to
  // the same as interrupt_test2() above).
  busy_loop();
  EXPECT_REPORT(x, 4, "?", x, 4, "w");
  intercept_reports_done();
  KEXPECT_EQ(2, *x);

  tsan_test_cleanup();
}


static void interrupt_tests(void) {
  interrupt_test1();
  interrupt_test1b();
  interrupt_test1c();
  interrupt_test1d();
  interrupt_test1e();
  interrupt_test2();
  interrupt_test3();
  interrupt_test4();
}

static void defint_fn(void* arg) {
  int* x = (int*)arg;
  tsan_rw_value(x);
}

static void defint_test1(void) {
  KTEST_BEGIN("TSAN: defint safety (DEFINT_PUSH_AND_DISABLE()");
  int* x = TS_MALLOC(int);
  *x = 0;
  tsan_rw_value(x);

  {
    // TODO(aoates): replace uses of DEFINT_PUSH_AND_DISABLE() with spinlocks,
    // and delete this test.
    DEFINT_PUSH_AND_DISABLE();
    defint_schedule(&defint_fn, x);
    tsan_rw_value(x);
    DEFINT_POP();
    KEXPECT_EQ(3, *x);
  }
  tsan_test_cleanup();
}

static void defint_test2(void) {
  KTEST_BEGIN("TSAN: defint safety (spinlock)");
  int* x = TS_MALLOC(int);
  *x = 0;
  tsan_rw_value(x);

  kspinlock_t mu = KSPINLOCK_NORMAL_INIT;
  {
    kspin_lock(&mu);
    defint_schedule(&defint_fn, x);
    tsan_rw_value(x);
    kspin_unlock(&mu);
    KEXPECT_EQ(3, *x);
  }
  tsan_test_cleanup();
}

static void defint_test3(void) {
  KTEST_BEGIN("TSAN: defint safety (intsafe spinlock)");
  int* x = TS_MALLOC(int);
  *x = 0;
  tsan_rw_value(x);

  kspinlock_intsafe_t mu = KSPINLOCK_INTERRUPT_SAFE_INIT;
  {
    kspin_lock_int(&mu);
    defint_schedule(&defint_fn, x);
    tsan_rw_value(x);
    kspin_unlock_int(&mu);
    busy_loop();  // Make sure the defint runs.

    // Make sure we can see the access the defint did.
    kspin_lock_int(&mu);
    tsan_rw_value(x);
    kspin_unlock_int(&mu);
    KEXPECT_EQ(4, *x);
  }
  tsan_test_cleanup();
}

static void defint_test3b(void) {
  KTEST_BEGIN("TSAN: defint safety (legacy interrupt disabling)");
  int* x = TS_MALLOC(int);
  *x = 0;
  tsan_rw_value(x);

  {
    PUSH_AND_DISABLE_INTERRUPTS();
    defint_schedule(&defint_fn, x);
    tsan_rw_value(x);
    POP_INTERRUPTS();
    busy_loop();  // Make sure the defint runs.
  }

  {
    // Make sure we can see the access the defint did.
    PUSH_AND_DISABLE_INTERRUPTS();
    tsan_rw_value(x);
    POP_INTERRUPTS();
    KEXPECT_EQ(4, *x);
  }
  tsan_test_cleanup();
}

static void schedule_defint_fn(void* arg) {
  KEXPECT_EQ(KTCTX_INTERRUPT, kthread_execution_context());
  defint_schedule(&defint_fn, arg);
}

static void defint_test4(void) {
  KTEST_BEGIN("TSAN: defint safety (defint scheduled from interrupt)");
  int* x = TS_MALLOC(int);
  *x = 0;

  kspinlock_t mu = KSPINLOCK_NORMAL_INIT;
  {
    register_event_timer(get_time_ms() + 10, &schedule_defint_fn, x, NULL);
    busy_loop();
    // Note: this is "getting lucky" (we're not explicitly synchronizing with
    // the defint, but relying on timing to get the ordering right).
    kspin_lock(&mu);
    tsan_rw_value(x);
    kspin_unlock(&mu);
    tsan_rw_value(x);
    KEXPECT_EQ(3, *x);
  }
  tsan_test_cleanup();
}

static void defint_test5(void) {
  KTEST_BEGIN("TSAN: defint safety (scheduling a defint synchronizes)");
  int* x = TS_MALLOC(int);
  *x = 0;

  tsan_rw_value(x);  // Should be synchronized by defint_schedule().
  defint_schedule(&defint_fn, x);
  busy_loop();  // Make sure the defint runs.

  KEXPECT_EQ(2, *x);
  tsan_test_cleanup();
}

static void defint_race_test1(void) {
  KTEST_BEGIN("TSAN: defint race (basic thread context/defint race)");
  int* x = TS_MALLOC(int);
  *x = 0;
  tsan_rw_value(x);

  intercept_reports();
  defint_schedule(&defint_fn, x);
  busy_loop();  // Make sure the defint runs.
  tsan_rw_value(x);
  EXPECT_REPORT(x, 4, "?", x, 4, "w");
  intercept_reports_done();
  tsan_test_cleanup();
}

static void defint_race_test2(void) {
  KTEST_BEGIN(
      "TSAN: defint race (basic thread context/interrupt-context defint race)");
  int* x = TS_MALLOC(int);
  *x = 0;

  intercept_reports();
  register_event_timer(get_time_ms() + 10, &schedule_defint_fn, x, NULL);
  busy_loop();
  tsan_rw_value(x);
  EXPECT_REPORT(x, 4, "?", x, 4, "w");
  intercept_reports_done();
  tsan_test_cleanup();
}

// Same as above, but races with an access before we register the timer.  This
// is safe.
static void defint_race_test3(void) {
  KTEST_BEGIN(
      "TSAN: defint race (basic thread context/interrupt-context defint race "
      "#2)");
  int* x = TS_MALLOC(int);
  *x = 0;
  tsan_rw_value(x);

  register_event_timer(get_time_ms() + 10, &schedule_defint_fn, x, NULL);
  busy_loop();
  // Safe -- the write above happens-before registering the timer, which
  // happens-before the interrupt, and therefore happens-before the defint.
  tsan_test_cleanup();
}

// Same as defint_race_test2, but try and race in the opposite order.
static void defint_race_test4(void) {
  KTEST_BEGIN(
      "TSAN: defint race (basic thread context/interrupt-context defint race "
      "#2)");
  int* x = TS_MALLOC(int);
  *x = 0;

  intercept_reports();
  register_event_timer(get_time_ms() + 10, &schedule_defint_fn, x, NULL);
  tsan_rw_value(x);
  busy_loop();
  EXPECT_REPORT(x, 4, "?", x, 4, "w");
  intercept_reports_done();
  tsan_test_cleanup();
}

static void defint_int_race_test1(void) {
  KTEST_BEGIN("TSAN: defint race (interrupt races with thread-ctx defint)");
  int* x = TS_MALLOC(int);
  *x = 0;
  kspinlock_t mu = KSPINLOCK_NORMAL_INIT;

  intercept_reports();
  register_event_timer(get_time_ms() + 10, &interrupt_fn, x, NULL);

  kspin_lock(&mu);
  defint_schedule(&defint_fn,  x);
  kspin_unlock(&mu);  // Should run defint synchronously.
  busy_loop();  // Make sure interrupt fires.
  busy_loop();
  EXPECT_REPORT(x, 4, "?", x, 4, "w");
  intercept_reports_done();
  KEXPECT_EQ(2, *x);
  tsan_test_cleanup();
}

static void slow_racy_defint(void* arg) {
  tsan_rw_value((int*)arg);
  busy_loop();
  tsan_rw_value((int*)arg);
}

// Similar to the above, but try and force the interrupt to interrupt the
// defint itself (rather than running before or after).
static void defint_int_race_test2(void) {
  KTEST_BEGIN("TSAN: defint race (interrupt INTERRUPTS thread-ctx defint)");
  int* x = TS_MALLOC(int);
  *x = 0;
  kspinlock_intsafe_t mu = KSPINLOCK_INTERRUPT_SAFE_INIT;

  intercept_reports();
  kspin_lock_int(&mu);
  register_event_timer(get_time_ms() + 10, &interrupt_fn, x, NULL);
  defint_schedule(&slow_racy_defint,  x);
  kspin_unlock_int(&mu);
  defint_process_queued(false);  // Should run defint synchronously.
  EXPECT_REPORT(x, 4, "?", x, 4, "w");
  intercept_reports_done();
  KEXPECT_EQ(3, *x);
  tsan_test_cleanup();
}

static void schedule_slow_racy_defint_fn(void* arg) {
  KEXPECT_EQ(KTCTX_INTERRUPT, kthread_execution_context());
  defint_schedule(&slow_racy_defint, arg);
}

static void schedule_slow_racy_defint_fn2(void* arg) {
  KEXPECT_EQ(KTCTX_INTERRUPT, kthread_execution_context());
  defint_schedule(&slow_racy_defint, arg);
  tsan_rw_value((int*)arg);
}

// Variant of the above where we do the access _before_ scheduling the defint,
// which is safe.
static void schedule_slow_racy_defint_fn3(void* arg) {
  KEXPECT_EQ(KTCTX_INTERRUPT, kthread_execution_context());
  tsan_rw_value((int*)arg);
  defint_schedule(&slow_racy_defint, arg);
}

static void defint_int_race_test3(void) {
  KTEST_BEGIN("TSAN: defint race (interrupt races with interrupt-ctx defint)");
  int* x = TS_MALLOC(int);
  *x = 0;

  intercept_reports();
  register_event_timer(get_time_ms() + 10, &schedule_slow_racy_defint_fn, x,
                       NULL);
  register_event_timer(get_time_ms() + 20, &interrupt_fn, x, NULL);

  busy_loop();  // Make sure interrupt fires.
  busy_loop();
  EXPECT_REPORT(x, 4, "?", x, 4, "w");
  intercept_reports_done();
  // Don't check the value of x --- the rw might be interrupted in a racy way
  // that causes its value to be either 1 or 2.
  tsan_test_cleanup();
}

// As above, but have it be the interrupt that scheduled the defint (and runs
// it) itself racing with the defint, rather than the defint being interrupted
// by a different (racing) interrupt.
static void defint_int_race_test4(void) {
  KTEST_BEGIN(
      "TSAN: defint race (interrupt races with interrupt-ctx defint #2)");
  int* x = TS_MALLOC(int);
  *x = 0;

  intercept_reports();
  register_event_timer(get_time_ms() + 10, &schedule_slow_racy_defint_fn2, x,
                       NULL);

  busy_loop();  // Make sure interrupt fires.
  busy_loop();
  EXPECT_REPORT(x, 4, "?", x, 4, "w");
  intercept_reports_done();
  KEXPECT_EQ(3, *x);
  tsan_test_cleanup();
}

// As above, but with a safe version.
static void defint_int_race_test5(void) {
  KTEST_BEGIN(
      "TSAN: defint race (interrupt races with interrupt-ctx defint #3)");
  int* x = TS_MALLOC(int);
  *x = 0;

  register_event_timer(get_time_ms() + 10, &schedule_slow_racy_defint_fn3, x,
                       NULL);

  busy_loop();  // Make sure interrupt fires.
  busy_loop();
  KEXPECT_EQ(3, *x);
  tsan_test_cleanup();
}

static void defint_tests(void) {
  defint_test1();
  defint_test2();
  defint_test3();
  defint_test3b();
  defint_test4();
  defint_test5();

  defint_race_test1();
  defint_race_test2();
  defint_race_test3();
  defint_race_test4();

  defint_int_race_test1();
  defint_int_race_test2();
  defint_int_race_test3();
  defint_int_race_test4();
  defint_int_race_test5();
}

static void interrupt_stack_writer(void* arg) {
  int vals[5];
  tsan_rw_value(&vals[0]);
  tsan_rw_value(&vals[1]);
  tsan_rw_value(&vals[2]);
  tsan_rw_value(&vals[3]);
  tsan_rw_value(&vals[4]);
}

static void interrupt_schedule_defint_stack_writer(void* arg) {
  defint_schedule(&interrupt_stack_writer, arg);
}

static void recurse_stack_writer(int n) {
  if (n == 0) return;
  recurse_stack_writer(n - 1);

  int vals[5];
  tsan_rw_value(&vals[0]);
  tsan_rw_value(&vals[1]);
  tsan_rw_value(&vals[2]);
  tsan_rw_value(&vals[3]);
  tsan_rw_value(&vals[4]);
}

static void interrupt_stack_test(void) {
  KTEST_BEGIN("TSAN: interrupt runs then function uses stack");
  int* x = TS_MALLOC(int);
  *x = 0;

  register_event_timer(get_time_ms() + 10, &interrupt_stack_writer, x, NULL);
  // Get the interrupt to run on our current stack.
  busy_loop();
  busy_loop();

  // Now use the stack.
  recurse_stack_writer(20);

  tsan_test_cleanup();
}

static void defint_stack_test(void) {
  KTEST_BEGIN("TSAN: defint runs then function uses stack");
  int* x = TS_MALLOC(int);
  *x = 0;

  register_event_timer(get_time_ms() + 10,
                       &interrupt_schedule_defint_stack_writer, x, NULL);
  // Get the interrupt/defint to run on our current stack.
  busy_loop();
  busy_loop();

  // Now use the stack.
  recurse_stack_writer(20);

  tsan_test_cleanup();
}

// TODO(tsan): write a test for the opposite race --- a thread uses its stack,
// then an interrupt fires.  Hard to do currently.

static void stack_tests(void) {
  interrupt_stack_test();
  defint_stack_test();
}

static void* sleep_then_access_u32(void* arg) {
  sched_enable_preemption_for_test();
  ksleep(30);
  tsan_unaligned_write32((uint32_t*)arg, 0x12345678);
  sched_disable_preemption();
  return NULL;
}

static void old_thread_test(void) {
  KTEST_BEGIN("TSAN: race with dead thread");
  uint64_t* x = TS_MALLOC(uint64_t);
  *x = 0;

  intercept_reports();
  tsan_rw_u64(x);
  kthread_t thread1, thread2;
  KEXPECT_EQ(0, proc_thread_create(&thread1, &access_u64, x));
  KEXPECT_EQ(0, proc_thread_create(&thread2, &sleep_then_access_u32, x));

  KEXPECT_EQ(NULL, kthread_join(thread1));
  KEXPECT_EQ(NULL, kthread_join(thread2));
  EXPECT_REPORT_NO_STACK(x, 4, "w", x, 8, "w");
  intercept_reports_done();

  tsan_test_cleanup();
}

static void tsan_memset_tests(void) {
  KTEST_BEGIN("TSAN: memset test");
  // We'll run tests for each byte position on both sides of the region.
  uint64_t* vals = tsan_test_alloc(8 * sizeof(uint64_t) * 3);

  // Repeatedly test memset()ing a 15-byte region at different offsets.
  for (int i = 0; i < 8; ++i) {
    uint8_t* vals8 = (uint8_t*)vals;
    tsan_write64(vals, 0);
    tsan_write64(vals + 1, 0);
    tsan_write64(vals + 2, 0);

    // Access the two bytes on either side of the memset region.  This is OK.
    kthread_t threads[3];
    KEXPECT_EQ(0, proc_thread_create(&threads[0], &access_u8, &vals8[i]));
    KEXPECT_EQ(0, proc_thread_create(&threads[1], &access_u8, &vals8[16 + i]));

    // ...and then memset all the bytes in between.
    KEXPECT_EQ(0, proc_thread_create(&threads[2], &access_memset_15bytes,
                                     &vals8[1 + i]));

    KEXPECT_EQ(NULL, kthread_join(threads[0]));
    KEXPECT_EQ(NULL, kthread_join(threads[1]));
    KEXPECT_EQ(NULL, kthread_join(threads[2]));

    KEXPECT_EQ(0x01, vals8[i]);
    for (int j = 0; j < 15; ++j) {
      KEXPECT_EQ(0x12, vals8[i + 1 + j]);
    }
    KEXPECT_EQ(0x01, vals8[16 + i]);

    vals += 3;
  }
  tsan_test_cleanup();
}

static void tsan_memset_conflict_tests(void) {
  KTEST_BEGIN("TSAN: memset conflict test");
  // We'll run tests for each byte position on both sides of the region.
  uint64_t* vals = tsan_test_alloc(8 * sizeof(uint64_t) * 3);

  // Repeatedly test memset()ing a 16-byte region at different offsets.
  for (int i = 0; i < 8; ++i) {
    uint8_t* vals8 = (uint8_t*)vals;
    tsan_write64(vals, 0);
    tsan_write64(vals + 1, 0);
    tsan_write64(vals + 2, 0);

    // #1: test for conflict on the "left" side of the region.
    kthread_t threads[2];
    intercept_reports();
    KEXPECT_EQ(0, proc_thread_create(&threads[0], &access_u8, &vals8[i]));
    KEXPECT_EQ(
        0, proc_thread_create(&threads[1], &access_memset_16bytes, &vals8[i]));

    KEXPECT_TRUE(wait_for_race());
    KEXPECT_EQ(NULL, kthread_join(threads[0]));
    KEXPECT_EQ(NULL, kthread_join(threads[1]));
    EXPECT_REPORT(&vals8[i], 1, "w", &vals8[i], 16, "w");
    intercept_reports_done();

    // #2: test for conflict on the middle of the region.
    intercept_reports();
    KEXPECT_EQ(0, proc_thread_create(&threads[0], &access_u8, &vals8[8]));
    KEXPECT_EQ(
        0, proc_thread_create(&threads[1], &access_memset_16bytes, &vals8[i]));

    KEXPECT_TRUE(wait_for_race());
    KEXPECT_EQ(NULL, kthread_join(threads[0]));
    KEXPECT_EQ(NULL, kthread_join(threads[1]));
    EXPECT_REPORT(&vals8[8], 1, "w", &vals8[i], 16, "w");
    intercept_reports_done();

    // #3: test for conflict on the "right" side of the region.
    intercept_reports();
    KEXPECT_EQ(0, proc_thread_create(&threads[0], &access_u8, &vals8[i + 15]));
    KEXPECT_EQ(
        0, proc_thread_create(&threads[1], &access_memset_16bytes, &vals8[i]));

    KEXPECT_TRUE(wait_for_race());
    KEXPECT_EQ(NULL, kthread_join(threads[0]));
    KEXPECT_EQ(NULL, kthread_join(threads[1]));
    EXPECT_REPORT(&vals8[i + 15], 1, "w", &vals8[i], 16, "w");
    intercept_reports_done();

    vals += 3;
  }
  tsan_test_cleanup();
}

static void tsan_implicit_memset_conflict_tests(void) {
  KTEST_BEGIN("TSAN: memset conflict test (compiler-generated memset)");
  tsan_test_struct_t* x = TS_MALLOC(tsan_test_struct_t);

  kthread_t threads[2];
  intercept_reports();
  KEXPECT_EQ(0, proc_thread_create(&threads[0], &access_u8, &x->e));
  KEXPECT_EQ(0, proc_thread_create(&threads[1], &access_implicit_memset, x));

  KEXPECT_TRUE(wait_for_race());
  KEXPECT_EQ(NULL, kthread_join(threads[0]));
  KEXPECT_EQ(NULL, kthread_join(threads[1]));
  EXPECT_REPORT(&x->e, 1, "w", x, sizeof(tsan_test_struct_t), "w");
  intercept_reports_done();

  tsan_test_cleanup();
}

static void tsan_memcpy_test(void) {
  KTEST_BEGIN("TSAN: memcpy (no conflict)");
  // Don't bother with complex address-range tests --- assume the memset tests
  // cover all those edge cases.
  uint8_t* vals_src = tsan_test_alloc(24);
  uint8_t* vals_dst = tsan_test_alloc(24);

  // We should be able to write both the source and destination on both sides of
  // the region, and read the source anywhere.
  for (int i = 0; i < 24; ++i) {
    vals_src[i] = 2;
    vals_dst[i] = 1;
  }

  const int kThreads = 10;
  kthread_t threads[kThreads];
  // First thread does the memcpy.
  access_memcpy_args_t args = {vals_dst + 1, vals_src + 2, 16};
  KEXPECT_EQ(0, proc_thread_create(&threads[0], &access_memcpy, &args));

  // These threads write on the edges of the src.
  KEXPECT_EQ(0, proc_thread_create(&threads[1], &access_u8, &vals_src[0]));
  KEXPECT_EQ(0, proc_thread_create(&threads[2], &access_u8, &vals_src[1]));
  KEXPECT_EQ(0, proc_thread_create(&threads[3], &access_u8, &vals_src[18]));
  KEXPECT_EQ(0, proc_thread_create(&threads[4], &access_u8, &vals_src[19]));

  // These threads write on the edges of the dst.
  KEXPECT_EQ(0, proc_thread_create(&threads[5], &access_u8, &vals_dst[0]));
  KEXPECT_EQ(0, proc_thread_create(&threads[6], &access_u8, &vals_dst[17]));

  // These threads read inside the src.
  KEXPECT_EQ(0, proc_thread_create(&threads[7], &read_u8, &vals_src[2]));
  KEXPECT_EQ(0, proc_thread_create(&threads[8], &read_u8, &vals_src[10]));
  KEXPECT_EQ(0, proc_thread_create(&threads[9], &read_u8, &vals_src[17]));

  for (int i = 0; i < kThreads; ++i) {
    KEXPECT_EQ(NULL, kthread_join(threads[i]));
  }

  KEXPECT_EQ(1, vals_dst[0]);
  for (int i = 0; i < 16; ++i) {
    KEXPECT_EQ(2, vals_dst[i + 1]);
  }
  KEXPECT_EQ(1, vals_dst[17]);

  tsan_test_cleanup();
}

static void tsan_memcpy_conflict_test(void) {
  KTEST_BEGIN("TSAN: memcpy (conflict)");
  uint8_t* vals_src = tsan_test_alloc(24);
  uint8_t* vals_dst = tsan_test_alloc(24);

  // We should be able to write both the source and destination on both sides of
  // the region, and read the source anywhere.
  for (int i = 0; i < 24; ++i) {
    vals_src[i] = 2;
    vals_dst[i] = 1;
  }

  // #1: a write inside the source should conflict.
  const int kThreads = 2;
  kthread_t threads[kThreads];
  intercept_reports();
  access_memcpy_args_t args = {vals_dst + 1, vals_src + 2, 16};
  KEXPECT_EQ(0, proc_thread_create(&threads[0], &access_memcpy, &args));
  KEXPECT_EQ(0, proc_thread_create(&threads[1], &access_u8, &vals_src[2]));

  KEXPECT_TRUE(wait_for_race());
  KEXPECT_EQ(NULL, kthread_join(threads[0]));
  KEXPECT_EQ(NULL, kthread_join(threads[1]));
  EXPECT_REPORT(&vals_src[2], 1, "w", &vals_src[2], 16, "r");
  intercept_reports_done();

  // #2: a write inside the source should conflict (at end).
  intercept_reports();
  KEXPECT_EQ(0, proc_thread_create(&threads[0], &access_memcpy, &args));
  KEXPECT_EQ(0, proc_thread_create(&threads[1], &access_u8, &vals_src[17]));

  KEXPECT_TRUE(wait_for_race());
  KEXPECT_EQ(NULL, kthread_join(threads[0]));
  KEXPECT_EQ(NULL, kthread_join(threads[1]));
  EXPECT_REPORT(&vals_src[17], 1, "w", &vals_src[2], 16, "r");
  intercept_reports_done();

  // #3: a write inside the dest should conflict.
  intercept_reports();
  KEXPECT_EQ(0, proc_thread_create(&threads[0], &access_memcpy, &args));
  KEXPECT_EQ(0, proc_thread_create(&threads[1], &access_u8, &vals_dst[1]));

  KEXPECT_TRUE(wait_for_race());
  KEXPECT_EQ(NULL, kthread_join(threads[0]));
  KEXPECT_EQ(NULL, kthread_join(threads[1]));
  EXPECT_REPORT(&vals_dst[1], 1, "w", &vals_dst[1], 16, "w");
  intercept_reports_done();

  // #4: a write inside the dest should conflict (at end).
  intercept_reports();
  KEXPECT_EQ(0, proc_thread_create(&threads[0], &access_memcpy, &args));
  KEXPECT_EQ(0, proc_thread_create(&threads[1], &access_u8, &vals_dst[16]));

  KEXPECT_TRUE(wait_for_race());
  KEXPECT_EQ(NULL, kthread_join(threads[0]));
  KEXPECT_EQ(NULL, kthread_join(threads[1]));
  EXPECT_REPORT(&vals_dst[16], 1, "w", &vals_dst[1], 16, "w");
  intercept_reports_done();

  // #5: a read inside the dest should conflict.
  intercept_reports();
  KEXPECT_EQ(0, proc_thread_create(&threads[0], &access_memcpy, &args));
  KEXPECT_EQ(0, proc_thread_create(&threads[1], &read_u8, &vals_dst[9]));

  KEXPECT_TRUE(wait_for_race());
  KEXPECT_EQ(NULL, kthread_join(threads[0]));
  KEXPECT_EQ(NULL, kthread_join(threads[1]));
  EXPECT_REPORT(&vals_dst[9], 1, "r", &vals_dst[1], 16, "w");
  intercept_reports_done();

  tsan_test_cleanup();
}

static void tsan_implicit_memcpy_conflict_tests(void) {
  KTEST_BEGIN("TSAN: memcpy conflict test (compiler-generated memcpy)");
  tsan_test_struct_t* x = TS_MALLOC(tsan_test_struct_t);

  kthread_t threads[2];
  intercept_reports();
  KEXPECT_EQ(0, proc_thread_create(&threads[0], &access_u8, &x->e));
  KEXPECT_EQ(0, proc_thread_create(&threads[1], &access_implicit_memcpy, x));

  KEXPECT_TRUE(wait_for_race());
  KEXPECT_EQ(NULL, kthread_join(threads[0]));
  KEXPECT_EQ(NULL, kthread_join(threads[1]));
  EXPECT_REPORT(&x->e, 1, "w", x, sizeof(tsan_test_struct_t), "w");
  intercept_reports_done();

  tsan_test_cleanup();
}

static void region_tests(void) {
  tsan_memset_tests();
  tsan_memset_conflict_tests();
  tsan_implicit_memset_conflict_tests();

  tsan_memcpy_test();
  tsan_memcpy_conflict_test();
  tsan_implicit_memcpy_conflict_tests();
}

void tsan_test(void) {
  KTEST_SUITE_BEGIN("TSAN");
  basic_tests();
  interrupt_tests();
  defint_tests();
  stack_tests();
  old_thread_test();
  region_tests();

  tsan_test_free_all();
}
