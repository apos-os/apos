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

#include "dev/devicetree/devicetree.h"

#include <stdalign.h>

#include "common/endian.h"
#include "common/kassert.h"
#include "common/kstring.h"
#include "common/math.h"
#include "dev/devicetree/dtb.h"
#include "user/include/apos/errors.h"

#define DT_MAX_DEPTH 10
#define DT_PROPVAL_ALIGN alignof(uint64_t)  // Sensible default

typedef struct {
  void* outbuf;
  size_t outbuf_len;
  size_t node_stack_len;
  dt_node_t* node_stack[DT_MAX_DEPTH];
  int num_phnodes;
  dt_tree_t* tree;
} parse_state_t;

static int align_parse(parse_state_t* parse, size_t align) {
  if (parse->outbuf_len < align) {
    return -1;
  }

  addr_t orig_addr = (addr_t)parse->outbuf;
  addr_t aligned_addr = align_up(orig_addr, align);
  parse->outbuf = (void*)aligned_addr;
  parse->outbuf_len -= aligned_addr - orig_addr;
  return 0;
}

static void* parse_alloc(parse_state_t* parse, size_t size, size_t align) {
  if (align_parse(parse, align) != 0) {
    return NULL;
  }
  if (parse->outbuf_len < size) {
    return NULL;
  }

  void* result = parse->outbuf;
  parse->outbuf += size;
  parse->outbuf_len -= size;
  return result;
}

#define ALLOC_STRUCT(_parse, _type) \
    (_type*)parse_alloc(_parse, sizeof(_type), alignof(_type));

static void* copy_buffer(parse_state_t* parse, size_t align, const void* src,
                         size_t len) {
  void* dst = parse_alloc(parse, len, align);
  if (!dst) return NULL;
  kmemcpy(dst, src, len);
  return dst;
}

static const char* copy_string(parse_state_t* parse, const char* str) {
  return copy_buffer(parse, /* align= */ 1, str, kstrlen(str) + 1);
}

bool node_begin_cb(const char* node_name, const dtfdt_node_context_t* context,
                   void* cbarg) {
  parse_state_t* parse = (parse_state_t*)cbarg;
  if (parse->node_stack_len >= DT_MAX_DEPTH) {
    return false;
  }

  dt_node_t* node = ALLOC_STRUCT(parse, dt_node_t);
  if (!node) {
    return false;
  }

  node->name = copy_string(parse, node_name);
  if (!node->name) {
    return false;
  }
  node->properties = NULL;
  node->children = NULL;
  node->next = NULL;
  node->context = *context;

  node->parent = NULL;
  if (parse->node_stack_len > 0) {
    node->parent = parse->node_stack[parse->node_stack_len - 1];
    node->next = node->parent->children;
    node->parent->children = node;
  }
  parse->node_stack[parse->node_stack_len] = node;
  ++parse->node_stack_len;
  return true;
}

bool node_end_cb(const char* node_name, void* cbarg) {
  parse_state_t* parse = (parse_state_t*)cbarg;
  dt_node_t* node = parse->node_stack[parse->node_stack_len - 1];
  KASSERT_DBG(kstrcmp(node->name, node_name) == 0);

  // Reverse property and children lists.
  dt_property_t* pprev, *pcurr;
  pprev = NULL;
  pcurr = node->properties;
  while (pcurr) {
    dt_property_t* pnext = pcurr->next;
    pcurr->next = pprev;
    pprev = pcurr;
    pcurr = pnext;
  }
  node->properties = pprev;

  dt_node_t* cprev, *ccurr;
  cprev = NULL;
  ccurr = node->children;
  while (ccurr) {
    dt_node_t* cnext = ccurr->next;
    ccurr->next = cprev;
    cprev = ccurr;
    ccurr = cnext;
  }
  node->children = cprev;

  parse->node_stack_len--;
  return true;
}

static void handle_phandle_prop(dt_node_t* node, const void* prop_val,
                                size_t val_len,
                                const dtfdt_node_context_t* context,
                                parse_state_t* parse) {
  if (val_len != sizeof(uint32_t)) {
    klog("Warning: found invalid phandle prop in devicetree\n");
    return;
  }
  if (parse->num_phnodes >= DT_TREE_MAX_PHNODES) {
    klog("Warning: ran out of space to store phandle values in devicetree\n");
    return;
  }
  dt_phandle_t val = btoh32(*(const dt_phandle_t*)prop_val);
  parse->tree->phnodes[parse->num_phnodes].phandle = val;
  parse->tree->phnodes[parse->num_phnodes].node = node;
  parse->num_phnodes++;
}

bool node_prop_cb(const char* prop_name, const void* prop_val, size_t val_len,
                  const dtfdt_node_context_t* context, void* cbarg) {
  parse_state_t* parse = (parse_state_t*)cbarg;
  dt_property_t* prop = ALLOC_STRUCT(parse, dt_property_t);
  if (!prop) {
    return false;
  }

  prop->name = copy_string(parse, prop_name);
  prop->val = copy_buffer(parse, DT_PROPVAL_ALIGN, prop_val, val_len);
  prop->val_len = val_len;
  if (!prop->name || !prop->val) {
    return false;
  }

  dt_node_t* node = parse->node_stack[parse->node_stack_len - 1];
  prop->next = node->properties;
  node->properties = prop;

  if (kstrcmp(prop_name, "phandle") == 0) {
    handle_phandle_prop(node, prop_val, val_len, context, parse);
  }
  return true;
}

dtfdt_parse_result_t dt_create(const void* fdt, dt_tree_t** tree_out,
                               void* out_buf, size_t buflen) {
  dtfdt_parse_cbs_t cbs = {
    .node_begin = &node_begin_cb,
    .node_end = &node_end_cb,
    .node_prop = &node_prop_cb,
  };
  parse_state_t parse;
  parse.outbuf = out_buf;
  parse.outbuf_len = buflen;
  parse.node_stack_len = 0;
  for (size_t i = 0; i < DT_MAX_DEPTH; ++i) {
    parse.node_stack[i] = NULL;
  }
  parse.num_phnodes = 0;

  dt_tree_t* tree = ALLOC_STRUCT(&parse, dt_tree_t);
  if (!tree) {
    return DTFDT_OUT_OF_MEMORY;
  }
  parse.tree = tree;
  for (int i = 0; i < DT_TREE_MAX_PHNODES; ++i) {
    tree->phnodes[i].phandle = 0;
    tree->phnodes[i].node = NULL;
  }

  dtfdt_parse_result_t result = dtfdt_parse(fdt, &cbs, &parse);
  if (result == DTFDT_STOPPED) {
    result = DTFDT_OUT_OF_MEMORY;
  }
  if (result != DTFDT_OK) {
    return result;
  }

  tree->buffer = out_buf;
  tree->root = parse.node_stack[0];
  KASSERT_DBG(*tree->root->name == '\0');
  *tree_out = tree;
  return DTFDT_OK;
}

const dt_node_t* dt_lookup(const dt_tree_t* tree, const char* path) {
  if (*path != '/') {
    return NULL;
  }

  // Special-case the root node, since its the only path allowed to end in '/'
  if (*(path + 1) == '\0') return tree->root;

  dt_node_t* node = tree->root;
  while (*path) {
    KASSERT_DBG(*path == '/');
    path++;
    const char* element_end = kstrchrnul(path, '/');
    size_t element_len = element_end - path;

    dt_node_t* child = node->children;
    node = NULL;  // Assume no match.
    while (child) {
      if ((size_t)kstrlen(child->name) == element_len &&
          kstrncmp(child->name, path, element_len) == 0) {
        node = child;
        break;
      }
      child = child->next;
    }
    if (!node) return NULL;
    path = element_end;
  }
  return node;
}

const dt_property_t* dt_get_prop(const dt_node_t* node, const char* prop_name) {
  dt_property_t* prop = node->properties;
  while (prop) {
    if (kstrcmp(prop->name, prop_name) == 0) return prop;
    prop = prop->next;
  }
  return NULL;
}

const dt_property_t* dt_get_nprop(const dt_tree_t* tree, const char* node_path,
                                  const char* prop_name) {
  const dt_node_t* node = dt_lookup(tree, node_path);
  if (!node) return NULL;
  return dt_get_prop(node, prop_name);
}

const dt_node_t* dt_lookup_phandle(const dt_tree_t* tree, dt_phandle_t ph) {
  for (int i = 0; i < DT_TREE_MAX_PHNODES; ++i) {
    if (tree->phnodes[i].phandle == ph) {
      return tree->phnodes[i].node;
    }
  }
  return NULL;
}

const dt_node_t* dt_lookup_prop_phandle(const dt_tree_t* tree,
                                        const dt_node_t* node,
                                        const char* prop_name) {
  const dt_property_t* prop = dt_get_prop(node, prop_name);
  if (!prop) {
    return NULL;
  }
  if (prop->val_len != sizeof(uint32_t)) {
    return NULL;
  }
  dt_phandle_t ph = btoh32(*(const dt_phandle_t*)prop->val);
  for (int i = 0; i < DT_TREE_MAX_PHNODES && tree->phnodes[i].node != NULL;
       ++i) {
    if (tree->phnodes[i].phandle == ph) {
      return tree->phnodes[i].node;
    }
  }
  return NULL;
}

const char* dt_get_unit(const dt_node_t* node) {
  const char* at = kstrchrnul(node->name, '@');
  if (*at) at++;
  return at;
}

static size_t path_printer(const dt_node_t* node, char* buf, size_t buflen) {
  // This is O(n^2) due to the kstrlcat()s, but that's fine.
  if (node->parent != NULL) {
    path_printer(node->parent, buf, buflen);
    kstrlcat(buf, "/", buflen);
  }
  return kstrlcat(buf, node->name, buflen);
}

size_t dt_print_path(const dt_node_t* node, char* buf, size_t buflen) {
  KASSERT(buflen > 1);
  if (node->parent == NULL) {
    kstrcpy(buf, "/");
    return 1;
  }
  buf[0] = '\0';
  return path_printer(node, buf, buflen);
}

int dt_parse_reg(const dt_node_t* node, dt_regval_t* out, int out_len) {
  const dt_property_t* reg = dt_get_prop(node, "reg");
  if (!reg) {
    return -ENOENT;
  }

  const int acells = node->context.address_cells;
  const int scells = node->context.size_cells;
  const size_t entry_size = (acells + scells) * sizeof(uint32_t);
  if (reg->val_len % entry_size != 0) {
    klog("Warning: malformed devicetree reg property\n");
    return -EINVAL;
  }

  if (acells < 1) {
    return -EINVAL;
  }

  _Static_assert(sizeof(addr_t) == sizeof(size_t), "weird type sizes");
  const int native_cells = sizeof(addr_t) / sizeof(uint32_t);
  // How many cells must be zero at the start of each address and size entry.
  const int addr_cells_zero =
      max(0, node->context.address_cells - native_cells);
  const int size_cells_zero = max(0, node->context.size_cells - native_cells);

  const int num_entries = reg->val_len / entry_size;
  if (num_entries == 0) {
    // It's possible this is valid, but it's not useful. Save callers a check.
    return -EINVAL;
  } else if (num_entries > out_len) {
    klog("Warning: not enough space to parse devicetree reg property\n");
    return -ENOMEM;
  }

  const uint32_t* cells = (const uint32_t*)reg->val;
  for (int entry = 0; entry < num_entries; ++entry) {
    out[entry].base = out[entry].len = 0;
    for (int i = 0; i < addr_cells_zero; ++i) {
      if (cells[i] != 0) {
        return -ERANGE;
      }
    }
    for (int i = 0; i < size_cells_zero; ++i) {
      if (cells[i + acells] != 0) {
        return -ERANGE;
      }
    }
#if ARCH_IS_64_BIT
    if (acells > 1) {
      out[entry].base += (uint64_t)btoh32(cells[acells - 2]) << 32;
    }
    if (scells > 1) {
      out[entry].len += (uint64_t)btoh32(cells[acells + scells - 2]) << 32;
    }
#endif
    out[entry].base += btoh32(cells[acells - 1]);
    if (scells > 0) {
      out[entry].len += btoh32(cells[acells + scells - 1]);
    }

    cells += acells + scells;
  }

  return num_entries;
}

int dt_get_prop_u32(const dt_node_t* node, const char* prop_name,
                    uint32_t* out) {
  const dt_property_t* prop = dt_get_prop(node, prop_name);
  if (!prop) {
    return -ENOENT;
  }

  if (prop->val_len != sizeof(uint32_t)) {
    return -EINVAL;
  }

  *out = btoh32(*(const uint32_t*)prop->val);
  return 0;
}

int dt_get_prop_int(const dt_node_t* node, const char* prop_name) {
  uint32_t val;
  int result = dt_get_prop_u32(node, prop_name, &val);
  if (result) {
    return result;
  }

  if (val > INT32_MAX) {
    return -ERANGE;
  }

  KASSERT_DBG((int)val >= 0);
  return (int)val;
}

bool dt_prop_streq(const dt_node_t* node, const char* prop_name,
                   const char* val) {
  const dt_property_t* prop = dt_get_prop(node, prop_name);
  if (!prop) {
    return false;
  }

  return (prop->val_len == (size_t)kstrlen(val) + 1) &&
         (kstrcmp(prop->val, val) == 0);
}
