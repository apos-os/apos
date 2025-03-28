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

#ifndef APOO_COMMON_KLOG_MODULES_H
#define APOO_COMMON_KLOG_MODULES_H

// Modules that can be logged at different levels independently.
typedef enum {
  KL_GENERAL = 0,

  // Memory modules.
  KL_BLOCK_CACHE,
  KL_KMALLOC,
  KL_PAGE_FAULT,
  KL_MEMORY,

  KL_PROC,
  KL_SYSCALL,

  // VFS modules.
  KL_EXT2,
  KL_VFS,

  // Device modules.
  KL_PCI,
  KL_NVME,
  KL_USB,
  KL_USB_HUB,
  KL_USB_UHCI,
  KL_TTY,

  // Networking modules.
  KL_NET,
  KL_TCP,

  KL_TEST,
  KL_USER,  // From userspace.

  KL_MODULE_MAX,
} klog_module_t;

// Return the string form of the klog module (e.g. KL_PCI -> "PCI").
const char* klog_module_name(klog_module_t m);

#endif
