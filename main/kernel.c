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
#include "main/kernel.h"

#include <stdint.h>

#include "arch/dev/irq.h"
#include "arch/memory/page_fault.h"
#include "arch/syscall/init.h"
#include "common/arch-config.h"
#include "common/config.h"
#include "common/errno.h"
#include "common/kassert.h"
#include "common/klog.h"
#include "common/kstring.h"
#include "dev/devicetree/devicetree.h"
#include "dev/devicetree/drivers.h"
#include "dev/interrupts.h"
#include "dev/serial/serial.h"
#include "dev/serial/uart16550.h"
#include "memory/kmalloc.h"
#include "net/init.h"
#include "proc/exec.h"
#include "proc/fork.h"
#include "proc/kthread.h"
#include "proc/process.h"
#include "proc/wait.h"
#include "memory/memory.h"
#include "dev/dev.h"
#include "dev/ps2.h"
#include "dev/keyboard/ps2_keyboard.h"
#include "dev/keyboard/keyboard.h"
#include "dev/ld.h"
#include "dev/ata/ata.h"
#include "dev/pci/pci.h"
#include "dev/video/vga.h"
#include "dev/video/vterm.h"
#include "dev/timer.h"
#include "dev/tty.h"
#include "main/kshell.h"
#include "memory/page_alloc.h"
#include "proc/scheduler.h"
#include "vfs/mount_table.h"
#include "vfs/vfs.h"
#include "test/ktest.h"
#include "test/kernel_tests.h"

#if ENABLE_USB
#include "dev/usb/usb.h"
#endif

#define LD_BUF_SIZE 1024

#define INIT_PATH "/sbin/init"

static vterm_t* g_vterm = 0;
static video_t* g_video = 0;
static apos_dev_t g_tty_dev = APOS_DEV_INVALID;

static void tick(void* arg) {
  static uint8_t i = 0;
  static const char* beat = "oO";
  i = (i + 1) % 2;

  video_setc(g_video, 0, video_get_width(g_video)-1, beat[i], VGA_DEFAULT_ATTR);
}

static void add_timers(void) {
  if (g_video) {
    KASSERT(0 == register_timer_callback(1000, 0, &tick, 0x0));
  }
}

static void legacy_io_init(void) {
  if (!ARCH_SUPPORTS_LEGACY_PC_DEVS) {
    return;
  }

  static vkeyboard_t* kbd = 0x0;
  kbd = vkeyboard_create();
  KASSERT(ps2_keyboard_init(kbd));

  video_vga_init();
  g_video = video_get_default();
  g_vterm = vterm_create(g_video);
  klog_set_vterm(g_vterm);
  klog_set_mode(KLOG_VTERM);

  ld_t* ld = ld_create(LD_BUF_SIZE);
  ld_set_sink(ld, &vterm_putc_sink, (void*)g_vterm);
  vterm_set_sink(g_vterm, &ld_provide_sink, ld);

  vkeyboard_set_handler(kbd, &ld_provide_sink, (void*)ld);

  // Create a TTY device.
  g_tty_dev = tty_create(ld);

  if (ARCH_SUPPORTS_LEGACY_PC_DEVS) {
    // Create the legacy serial port.
    apos_dev_t serial_tty;
    u16550_create_legacy(&serial_tty);
  }
}

// Does a relatively static devicetree-based init, looking for /chosen and
// assuming stdout-path points at a serial device.
// TODO(aoates): get bootargs from /chosen and do something with it.
static void dtree_io_init(void) {
  const dt_tree_t* dtree = get_boot_info()->dtree;
  if (!dtree) {
    die("No devicetree found");
  }

  const dt_property_t* prop = dt_get_nprop(dtree, "/chosen", "stdout-path");
  if (!prop) {
    die("Unable to find /chosen:stdout-path in devicetree");
  }
  const char* stdout_path = (const char*)prop->val;
  // TODO(aoates): make this a common helper (for getting and validating
  // different types of values from properties).
  if (stdout_path[prop->val_len - 1] != '\0') {
    die("Invalid stdout-path string");
  }

  const dt_node_t* serial = dt_lookup(dtree, stdout_path);
  if (!serial) {
    klogfm(KL_GENERAL, FATAL, "Unable to find stdout-path node '%s'\n",
           stdout_path);
  }
  klogf("Found /chosen:stdout-path: '%s', looking for driver\n", stdout_path);
  dt_driver_info_t* driver = dtree_get_driver(serial);
  if (!driver || kstrcmp(driver->type, "serial") != 0) {
    klogfm(KL_GENERAL, FATAL, "Unable to open node '%s' as serial device\n",
           stdout_path);
  }
  serial_driver_data_t* serial_data = (serial_driver_data_t*)driver->data;
  g_tty_dev = serial_data->chardev;
}

static void io_init(void) {
  if (ARCH_SUPPORTS_LEGACY_PC_DEVS) {
    legacy_io_init();
  } else {
    dtree_io_init();
  }
}

static void init_trampoline(void* arg) {
  char* argv[] = {INIT_PATH, NULL};
  char* envp[] = {NULL};
  int result = do_execve(INIT_PATH, argv, envp, NULL, NULL);
  KASSERT(result != 0);
  klogf("Unable to exec " INIT_PATH ": %s\n", errorname(-result));
  if (g_tty_dev == APOS_DEV_INVALID) {
    klogf("No default TTY found, cannot launch kshell.\n");
    return;
  }
  klogf("Launching kshell instead.\n");
  kshell_main(g_tty_dev);
}

const boot_info_t* g_boot_info = NULL;
const boot_info_t* get_boot_info(void) {
  return g_boot_info;
}

void kmain(const boot_info_t* boot) {
  g_boot_info = boot;
  set_global_meminfo(boot->meminfo);

  klog_set_mode(KLOG_RAW_VIDEO);
  klog("\n\n@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n");
  klog(    "@                          APOO                           @\n");
  klog(    "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n");

  // Initialize core low-level hardware.
  klog("interrupts_init()\n");
  interrupts_init();
  klog("arch_irq_init()\n");
  arch_irq_init();

  enable_interrupts();

  // Initialize memory systems.
  klog("page_frame_alloc_init()\n");
  page_frame_alloc_init(boot->meminfo);
  klog("paging_init()\n");
  paging_init();

  klog("proc_init_stage1()\n");
  proc_init_stage1();

  klog("kmalloc_init()\n");
  kmalloc_init();

  // Initialize proc, thread, and scheduler systems.
  klog("kthread_init()\n");
  kthread_init();

  klog("timer_init()\n");
  timer_init();
  add_timers();

  klog("scheduler_init()\n");
  scheduler_init();

  klog("proc_init_stage2()\n");
  proc_init_stage2();

  // Initialize devices.
  if (boot->dtree) {
    dtree_load_drivers(boot->dtree);
  }

  klog("pci_init()\n");
  pci_init();

  klog("ps2_init()\n");
  ps2_init();

  io_init();

  klog("ata_init()\n");
  ata_init();

#if ENABLE_USB
  klog("usb_init()\n");
  usb_init();
#endif

  // Initialize higher-level systems.
  klog("vfs_init()\n");
  vfs_init();

  klog("syscalls_init()\n");
  syscalls_init();

  dev_init_fs();

  vfs_apply_mount_table();

  klog("net_init()\n");
  net_init();

  klog("initialization finished...\n");

  if (g_vterm) {
    vterm_clear(g_vterm);
  }
  klog("APOO\n");

  const memory_info_t* m = boot->meminfo;
  klogf("meminfo: %p\n", boot->meminfo);
  klogf("meminfo->kernel_start_phys:   0x%" PRIxADDR "\n", m->kernel.phys.base);
  klogf("meminfo->kernel_end_phys:     0x%" PRIxADDR "\n",
        m->kernel.phys.base + m->kernel.phys.len);
  klogf("meminfo->kernel_start_virt:   0x%" PRIxADDR "\n", m->kernel.virt_base);
  klogf("meminfo->kernel_end_virt:     0x%" PRIxADDR "\n",
        m->kernel.virt_base + m->kernel.phys.len);
  klogf("meminfo->mapped_start:        0x%" PRIxADDR "\n",
        m->kernel_mapped.base);
  klogf("meminfo->mapped_end:          0x%" PRIxADDR "\n",
        m->kernel_mapped.base + m->kernel_mapped.len);
  klogf("meminfo->mainmem_phys:        0x%" PRIxADDR "\n",
        m->mainmem_phys.base);
  klogf("meminfo->mainmem_len:         0x%" PRIxADDR "\n", m->mainmem_phys.len);
  klogf("meminfo->phys_map_start:      0x%" PRIxADDR "\n",
        m->phys_map.virt_base);
  klogf("meminfo->phys_map_length:     0x%" PRIxADDR "\n",
        m->phys_map.phys.len);

  // TODO(aoates): reparent processes to the init process rather than the kernel
  // process?  Or run init in the kernel process (exec without fork below)?
  const kpid_t shell_pid = proc_fork(&init_trampoline, 0x0);
  if (shell_pid < 0) {
    klogf("proc_fork error: %s\n", errorname(-shell_pid));
    die("unable to fork process 0 to create kshell");
  }

  // Collect zombie children until the shell exits.
  kpid_t child_pid;
  do {
    child_pid = proc_wait(0x0);
  } while (child_pid != shell_pid);

  klog("DONE\n");
}
