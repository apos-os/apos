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

#include "dev/devicetree/drivers.h"

#include <stdbool.h>

#include "common/errno.h"
#include "common/hash.h"
#include "common/hashtable.h"
#include "common/kassert.h"
#include "common/kstring.h"
#include "dev/devicetree/devicetree.h"
#include "dev/rtc/goldfish-rtc.h"
#include "dev/serial/uart16550.h"
#include "memory/kmalloc.h"
#include "proc/kthread.h"

#define KLOG(...) klogfm(KL_GENERAL, __VA_ARGS__)

// Very basic driver mechanism.
typedef struct {
  const char* name;

  // A list of `compatible` strings this driver is compatible with.  For a
  // device, we examine each value in the `compatible` list and find the first
  // driver that matches.  NULL-terminated.
  const char* const* compatible;

  // Driver initialization function.  Takes a compatible dt_node_t* and fills in
  // the driver data.  Returns 0 or -error.
  int (*adopt)(const dt_tree_t*, const dt_node_t*, dt_driver_info_t*);
} dt_driver_t;

// TODO(aoates): consider consolidating driver lists (between here, PCI, USB,
// etc) to reduce duplication.

static dt_driver_t DTREE_DRIVERS[] = {
    {"goldfish-rtc", (const char*[]){"google,goldfish-rtc", NULL},
     &goldfish_rtc_driver},

    {"uart16550", (const char*[]){"ns16550a", NULL}, &u16550_driver},

    {NULL, NULL, NULL},
};

// Global driver table.
static htbl_t g_node_drivers;
static kmutex_t g_dt_lock;
static bool g_init = false;

typedef uint32_t node_key_t;
static node_key_t node_key(const dt_node_t* node) {
  return fnv_hash_addr((addr_t)node);
}

static dt_driver_info_t* find_driver_one(const dt_tree_t* tree,
                                         const dt_node_t* node,
                                         const char* node_path,
                                         const char* compat) {
  for (int i = 0; DTREE_DRIVERS[i].name != NULL; ++i) {
    for (int j = 0; DTREE_DRIVERS[i].compatible[j] != NULL; j++) {
      if (kstrcmp(compat, DTREE_DRIVERS[i].compatible[j]) == 0) {
        dt_driver_info_t* driver =
            (dt_driver_info_t*)kmalloc(sizeof(dt_driver_info_t));
        KASSERT(driver != NULL);
        kmemset(driver, 0, sizeof(dt_driver_info_t));
        driver->name = DTREE_DRIVERS[i].name;
        driver->type = "unknown";
        driver->node = node;

        int result = DTREE_DRIVERS[i].adopt(tree, node, driver);
        if (result) {
          KLOG(WARNING, "Failed to initialize driver %s for node %s: %s\n",
               DTREE_DRIVERS[i].name, node_path, errorname(-result));
          kfree(driver);
          continue;
        }

        return driver;
      }
    }
  }

  return NULL;
}

// Looks for a driver for the node and returns a dt_driver_info_t* if found, or
// NULL.
static dt_driver_info_t* find_driver(const dt_tree_t* tree,
                                     const dt_node_t* node,
                                     const char* node_path) {
  const dt_property_t* compat = dt_get_prop(node, "compatible");
  if (!compat) {
    KLOG(DEBUG2, "Node %s has no 'compatible' property; skipping\n", node_path);
    return NULL;
  }

  const char* compat_str = (const char*)compat->val;
  size_t compat_len = compat->val_len;
  while (compat_len > 0) {
    size_t len = kstrnlen(compat_str, compat_len);
    if (len >= compat_len) {
      KLOG(WARNING, "devicetree node %s has malformed 'compatible' property\n",
           node_path);
      return NULL;
    }

    dt_driver_info_t* driver =
        find_driver_one(tree, node, node_path, compat_str);
    if (driver) {
      return driver;
    }

    KASSERT_DBG(compat_str[len] == '\0');
    KASSERT_DBG(compat_len >= len + 1);
    compat_str += len + 1;
    compat_len -= len + 1;
  }

  return NULL;
}

// Recursively find and initialize drivers for this node and its children.
static void init_drivers(const dt_tree_t* tree, const dt_node_t* node,
                         char* node_path_buf) {
  if (dt_print_path(node, node_path_buf, DT_NODE_PATH_LEN) > DT_NODE_PATH_LEN) {
    KLOG(WARNING, "devicetree node path truncated (node=%p, path=%s)\n", node,
         node_path_buf);
  }

  dt_driver_info_t* driver = find_driver(tree, node, node_path_buf);
  if (!driver) {
    KLOG(DEBUG, "No driver found for node %s\n", node_path_buf);
  } else {
    KLOG(INFO, "Initialized driver %s for node %s\n", driver->name,
         node_path_buf);
    node_key_t key = node_key(node);
    void* val;
    KASSERT_MSG(htbl_get(&g_node_drivers, key, &val) != 0,
                "Multiple drivers loaded for node %s\n", node_path_buf);
    htbl_put(&g_node_drivers, key, driver);
  }

  const dt_node_t* child = node->children;
  while (child) {
    init_drivers(tree, child, node_path_buf);
    // node_path_buf has been dirtied!
    child = child->next;
  }
}

void dtree_load_drivers(const dt_tree_t* tree) {
  KASSERT(!g_init);
  kmutex_init(&g_dt_lock);
  htbl_init(&g_node_drivers, 10);
  g_init = true;

  // For each node in the tree, try and find an appropriate driver.
  kmutex_lock(&g_dt_lock);
  char path[DT_NODE_PATH_LEN];
  init_drivers(tree, tree->root, path);
  kmutex_unlock(&g_dt_lock);
}

dt_driver_info_t* dtree_get_driver(const dt_node_t* node) {
  KASSERT(g_init);

  node_key_t key = node_key(node);
  void* val;
  dt_driver_info_t* result = NULL;

  kmutex_lock(&g_dt_lock);
  if (htbl_get(&g_node_drivers, key, &val) == 0) {
    result = (dt_driver_info_t*)val;
  }
  kmutex_unlock(&g_dt_lock);

  return result;
}
