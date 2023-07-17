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

#include "common/kassert.h"
#include "common/kstring.h"
#include "common/math.h"
#include "dev/devicetree/dtb.h"

#define DT_MAX_DEPTH 10
#define DT_PROPVAL_ALIGN alignof(uint64_t)  // Sensible default

typedef struct {
  void* outbuf;
  size_t outbuf_len;
  size_t node_stack_len;
  dt_node_t* node_stack[DT_MAX_DEPTH];
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

  if (parse->node_stack_len > 0) {
    dt_node_t* parent = parse->node_stack[parse->node_stack_len - 1];
    node->next = parent->children;
    parent->children = node;
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

  dt_tree_t* tree = ALLOC_STRUCT(&parse, dt_tree_t);
  if (!tree) {
    return DTFDT_OUT_OF_MEMORY;
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
