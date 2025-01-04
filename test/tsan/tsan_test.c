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
#include "dev/interrupts.h"
#include "dev/timer.h"
#include "memory/kmalloc.h"
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
                          void* addr2, int size2, const char* type2,
                          bool try_swap) {
  bool v = true;
  v &= KEXPECT_TRUE(g_found_report);
  if (!g_found_report) return v;

  // Try it swapped as well.
  if (try_swap && ((addr_t)addr1 != g_report.race.cur.addr ||
                   size1 != g_report.race.cur.size ||
                   !type_matches(type1, g_report.race.cur.type))) {
    return expect_report(addr2, size2, type2, addr1, size1, type1, false);
  }

  v &= KEXPECT_EQ((addr_t)addr1, g_report.race.cur.addr);
  v &= KEXPECT_EQ(size1, g_report.race.cur.size);
  v &= type_matches(type1, g_report.race.cur.type);
  v &= KEXPECT_EQ((addr_t)addr2, g_report.race.prev.addr);
  v &= KEXPECT_EQ(size2, g_report.race.prev.size);
  v &= type_matches(type2, g_report.race.prev.type);

  // Crude stack trace checking.
  v &= KEXPECT_NE(0, g_report.race.cur.trace[0]);
  v &= KEXPECT_NE(0, g_report.race.cur.trace[1]);
  v &= KEXPECT_NE(0, g_report.race.prev.trace[0]);
  v &= KEXPECT_NE(0, g_report.race.prev.trace[1]);

  kmemset(&g_report, 0, sizeof(g_report));
  return v;
}

#define EXPECT_REPORT(addr1, size1, type1, addr2, size2, type2) \
  KEXPECT_TRUE(expect_report(addr1, size1, type1, addr2, size2, type2, true))

/************************** Tests ************************************/
typedef struct {
  kmutex_t mu;
  uint64_t* val;
} mutex_test_args_t;

static void tsan_basic_sanity_test(void) {
  KTEST_BEGIN("TSAN: basic R/W heap value instrumentation");
  int* x = KMALLOC(int);
  *x = 0;
  tsan_rw_value(x);
  KEXPECT_EQ(1, *x);
  tsan_rw_value(x);
  KEXPECT_EQ(2, *x);
  tsan_rw_value(x);
  KEXPECT_EQ(3, *x);
  kfree(x);
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
  int* x = KMALLOC(int);
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
  ksleep(10);
  tsan_rw_value(x);
  EXPECT_REPORT(x, 4, "w", x, 4, "?");

  KEXPECT_EQ(NULL, kthread_join(thread));
  intercept_reports_done();

  kfree(x);
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
  args.val = kmalloc(sizeof(uint64_t) * 4);
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
  kfree(args.val);
}

// As above, but sleep after thread creation to test passing values without
// locking to a new thread (which should be allowed).
static void tsan_basic_sanity_test4(void) {
  KTEST_BEGIN("TSAN: basic R/W heap value (two threads, locked, sleep)");
  mutex_test_args_t args;
  kmutex_init(&args.mu);
  args.val = kmalloc(sizeof(uint64_t) * 4);
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
  kfree(args.val);
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
  uint64_t* vals = kmalloc(sizeof(uint64_t) * 8);
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
  kfree(vals);
}

// As above, but with concurrent 1-byte/2-byte accesses.
static void size2_safe_test(void) {
  KTEST_BEGIN("TSAN: two threads accessing different 2 bytes is safe");
  uint64_t* vals = kmalloc(sizeof(uint64_t) * 8);
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
  kfree(vals);
}

// As above, but with concurrent 1-byte/4-byte accesses.
static void size4_safe_test(void) {
  KTEST_BEGIN("TSAN: two threads accessing different 4 bytes is safe");
  uint64_t* vals = kmalloc(sizeof(uint64_t) * 8);
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
  kfree(vals);
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
  uint64_t* val = KMALLOC(uint64_t);
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
  kfree(val);
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
  uint64_t* vals = kmalloc(sizeof(uint64_t) * 6);
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

  kfree(vals);
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

static void unaligned_overlap_2byte_test(void) {
  KTEST_BEGIN("TSAN: unaligned 2-byte access that straddles two shadow cells");
  uint64_t* vals = kmalloc(sizeof(uint64_t) * 2);
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
  kfree(vals);
}

static void unaligned_overlap_2byte_conflict_test(void) {
  KTEST_BEGIN(
      "TSAN: unaligned 2-byte access that straddles two shadow cells "
      "(conflict)");
  uint64_t* vals = kmalloc(sizeof(uint64_t) * 2);
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

  KEXPECT_EQ(NULL, kthread_join(threads[0]));
  KEXPECT_EQ(NULL, kthread_join(threads[1]));

  // We should have gotten a conflict.
  EXPECT_REPORT(&vals8[8], 1, "w", &vals8[7], 2, "w");
  intercept_reports_done();

  kfree(vals);
}

static void unaligned_overlap_4byte_test(void) {
  KTEST_BEGIN("TSAN: unaligned 4-byte access that straddles two shadow cells");
  uint64_t* vals = kmalloc(sizeof(uint64_t) * 2);
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
  kfree(vals);
}

static void unaligned_overlap_4byte_conflict_test(void) {
  KTEST_BEGIN(
      "TSAN: unaligned 4-byte access that straddles two shadow cells "
      "(conflict)");
  uint64_t* vals = kmalloc(sizeof(uint64_t) * 2);
  uint8_t* vals8 = (uint8_t*)vals;

  for (int i = 0; i < 4; ++i) {
    tsan_write64(vals, 0);
    tsan_write64(vals + 1, 0);

    kthread_t threads[2];
    intercept_reports();
    KEXPECT_EQ(0, proc_thread_create(&threads[0], &access_u8, &vals8[5 + i]));

    // ...and then access the straddled uint32_t.
    KEXPECT_EQ(0, proc_thread_create(&threads[1], &access_u32, &vals8[5]));

    KEXPECT_EQ(NULL, kthread_join(threads[0]));
    KEXPECT_EQ(NULL, kthread_join(threads[1]));

    // We should have gotten a conflict.
    EXPECT_REPORT(&vals8[5 + i], 1, "w", &vals8[5], 4, "w");
    intercept_reports_done();
  }
  kfree(vals);
}

static void unaligned_overlap_8byte_test(void) {
  KTEST_BEGIN("TSAN: unaligned 8-byte access that straddles two shadow cells");
  uint64_t* vals = kmalloc(sizeof(uint64_t) * 2);
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
  kfree(vals);
}

static void unaligned_overlap_8byte_conflict_test(void) {
  KTEST_BEGIN(
      "TSAN: unaligned 8-byte access that straddles two shadow cells "
      "(conflict)");
  uint64_t* vals = kmalloc(sizeof(uint64_t) * 2);
  uint8_t* vals8 = (uint8_t*)vals;

  for (int i = 0; i < 8; ++i) {
    tsan_write64(vals, 0);
    tsan_write64(vals + 1, 0);

    kthread_t threads[2];
    intercept_reports();
    KEXPECT_EQ(0, proc_thread_create(&threads[0], &access_u8, &vals8[1 + i]));

    // ...and then access the straddled uint32_t.
    KEXPECT_EQ(0, proc_thread_create(&threads[1], &access_u64, &vals8[1]));

    KEXPECT_EQ(NULL, kthread_join(threads[0]));
    KEXPECT_EQ(NULL, kthread_join(threads[1]));

    // We should have gotten a conflict.
    EXPECT_REPORT(&vals8[1 + i], 1, "w", &vals8[1], 8, "w");
    intercept_reports_done();
  }
  kfree(vals);
}

static void basic_tests(void) {
  tsan_basic_sanity_test();
  tsan_basic_sanity_test2();
  tsan_basic_sanity_test3();
  tsan_basic_sanity_test4();
  size1_safe_test();
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
  int* x = KMALLOC(int);
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
  kfree(x);
}

static void interrupt_test1b(void) {
  KTEST_BEGIN("TSAN: interrupt-safety (with kspinlock_int)");
  int* x = KMALLOC(int);
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
  kfree(x);
}

static void interrupt_test1c(void) {
  KTEST_BEGIN("TSAN: interrupt-safety (with scheduler_wait_on() timeout)");
  int* x = KMALLOC(int);
  *x = 0;
  tsan_rw_value(x);

  kthread_queue_t q;
  kthread_queue_init(&q);
  KEXPECT_EQ(SWAIT_TIMEOUT, scheduler_wait_on_interruptable(&q, 20));
  kfree(x);
}

// As above, but with interrupts disabled (so that POP_INTERRUPTS() calls in
// scheduler_wait_on_interruptable() don't do anything).
static void interrupt_test1d(void) {
  KTEST_BEGIN("TSAN: interrupt-safety (with scheduler_wait_on() timeout #2)");
  int* x = KMALLOC(int);
  *x = 0;
  tsan_rw_value(x);

  kthread_queue_t q;
  kthread_queue_init(&q);
  PUSH_AND_DISABLE_INTERRUPTS();
  KEXPECT_EQ(SWAIT_TIMEOUT, scheduler_wait_on_interruptable(&q, 20));
  POP_INTERRUPTS();
  kfree(x);
}

// As above, but also with an unsynchronized thread that can run while we're
// waiting.
static void interrupt_test1e(void) {
  KTEST_BEGIN("TSAN: interrupt-safety (with scheduler_wait_on() timeout #3)");
  int* x = KMALLOC(int);
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
  kfree(x);
}

static void interrupt_test2(void) {
  KTEST_BEGIN("TSAN: interrupt-safety (conflict)");
  int* x = KMALLOC(int);
  *x = 0;

  intercept_reports();
  tsan_rw_value(x);

  register_event_timer(get_time_ms() + 10, &interrupt_fn, x, NULL);
  busy_loop();
  tsan_rw_value(x);
  EXPECT_REPORT(x, 4, "r", x, 4, "w");
  intercept_reports_done();
  KEXPECT_EQ(3, *x);

  kfree(x);
}

// Slight variant on the above where we write to the value _after_ we schedule
// the interrupt.
static void interrupt_test3(void) {
  KTEST_BEGIN("TSAN: interrupt-safety (conflict #2)");
  int* x = KMALLOC(int);
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

  kfree(x);
}

// Combo test where thread 1 races with thread 2 by sleeping in an
// interrupt-disabled critical section (which, FWIW, is incorrect).
static void interrupt_test4(void) {
  KTEST_BEGIN("TSAN: interrupt-safety (conflict #2)");
  int* x = KMALLOC(int);
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

  kfree(x);
}

// TODO(tsan): test interrupt races with defint that is itself running in an
// interrupt (and running normally).

static void interrupt_tests(void) {
  interrupt_test1();
  interrupt_test1b();
  interrupt_test1c();
  interrupt_test1d();
  interrupt_test1e();
  interrupt_test2();
  interrupt_test3();
}

void tsan_test(void) {
  KTEST_SUITE_BEGIN("TSAN");
  basic_tests();
  interrupt_tests();
}
