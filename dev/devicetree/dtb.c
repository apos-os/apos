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

#include "dev/devicetree/dtb.h"

#include <stdbool.h>
#include <stdint.h>

#include "common/config.h"
#include "common/endian.h"
#include "common/errno.h"
#include "common/kprintf.h"
#include "common/kstring.h"
#include "common/math.h"
#include "common/types.h"

// FDT tokens.
#define FDT_BEGIN_NODE 1
#define FDT_END_NODE 2
#define FDT_PROP 3
#define FDT_NOP 4
#define FDT_END 9

int dtfdt_validate(const void* buf, fdt_header_t* header) {
  const fdt_header_t_bige* hdr_in = buf;
  if (btoh32(hdr_in->magic) != 0xd00dfeed) {
    return -EINVAL;
  }
  kmemcpy(header, buf, sizeof(fdt_header_t));
  header->magic = btoh32(header->magic);
  header->totalsize = btoh32(header->totalsize);
  header->off_dt_struct = btoh32(header->off_dt_struct);
  header->off_dt_strings = btoh32(header->off_dt_strings);
  header->off_mem_rsvmap = btoh32(header->off_mem_rsvmap);
  header->version = btoh32(header->version);
  header->last_comp_version = btoh32(header->last_comp_version);
  header->boot_cpuid_phys = btoh32(header->boot_cpuid_phys);
  header->size_dt_strings = btoh32(header->size_dt_strings);
  header->size_dt_struct = btoh32(header->size_dt_struct);

  if (header->last_comp_version > DTFDT_VERSION) {
    return -EINVAL;
  }

  return 0;
}

typedef struct {
  const char* fdt;  // The overall FDT
  const char* fdtstruct;  // The dtstruct pointer.
  const fdt_header_t* hdr;
  size_t pos;
  size_t buflen;
  const dtfdt_parse_cbs_t* cbs;
  void* cbarg;
} fdt_parse_state_t;

static void node_context_defaults(dtfdt_node_context_t* ctx) {
  ctx->address_cells = 2;
  ctx->size_cells = 1;
}

// Consume and return a uint32_t from the buffer.
static dtfdt_parse_result_t consume_u32(fdt_parse_state_t* parse,
                                        uint32_t* val) {
  if (parse->pos % sizeof(uint32_t) != 0) {
    return DTFDT_BAD_ALIGNMENT;
  }
  if (parse->pos + sizeof(uint32_t) > parse->buflen) {
    return DTFDT_BUF_TOO_SHORT;
  }
  const uint32_t* buf_tok = (const uint32_t*)(parse->fdtstruct + parse->pos);
  *val = btoh32(*buf_tok);
  parse->pos += sizeof(uint32_t);
  return DTFDT_OK;
}

// Advance the parse past any NOPs to the next token, consume it, and return its
// value.  If we hit the end of the buffer before we hit a non-NOP, returns -1
// (this is a parse error).
static int consume_next_token(fdt_parse_state_t* parse) {
  uint32_t tok;
  do {
    dtfdt_parse_result_t status = consume_u32(parse, &tok);
    if (status != DTFDT_OK) return status;
  } while (tok == FDT_NOP);
  switch (tok) {
    case FDT_BEGIN_NODE:
    case FDT_END_NODE:
    case FDT_PROP:
    case FDT_NOP:
    case FDT_END:
      return tok;
  }
  return DTFDT_BAD_TOKEN;
}

// Returns the length of the node name if valid, or -1.
static int validate_node_name(const fdt_parse_state_t* parse,
                              const char* name) {
  size_t maxlen = parse->buflen - parse->pos;
  // TODO(aoates): consider validating the contents as well as the length.
  for (size_t i = 0; i < maxlen; ++i) {
    if (name[i] == '\0') return i;
  }
  return -1;
}

// Attempt to parse out a special property, setting the given value if the
// property name matches.  If the property name doesn't match, succeeds without
// doing anything.
static dtfdt_parse_result_t parse_int_prop(const fdt_parse_state_t* parse,
                                           const char* prop_name,
                                           uint32_t prop_len,
                                           const char* expected_prop_name,
                                           int* val_out) {
  if (kstrcmp(prop_name, expected_prop_name) == 0) {
    if (prop_len != sizeof(uint32_t)) return DTFDT_BAD_PROPERTY;
    uint32_t val = btoh32(*(const uint32_t*)(parse->fdtstruct + parse->pos));
    // Basic reasonableness checking.
    if (val > UINT16_MAX) return DTFDT_BAD_PROPERTY;
    *val_out = (int)val;
  }
  return DTFDT_OK;
}

static dtfdt_parse_result_t parse_node(fdt_parse_state_t* parse,
                                       const dtfdt_node_context_t* ctx) {
  // Assume that the FDT_BEGIN_NODE token has already been consumed.
  const char* node_name = parse->fdtstruct + parse->pos;
  int result = validate_node_name(parse, node_name);
  if (result < 0) {
    return DTFDT_BAD_NAME;
  }
  parse->pos += result + 1;  // Consume name and NULL.
  parse->pos = align_up(parse->pos, sizeof(uint32_t));
  parse->cbs->node_begin(node_name, ctx, parse->cbarg);

  // Our children don't inherit our parent's size settings; reset to default.
  dtfdt_node_context_t child_ctx;
  node_context_defaults(&child_ctx);

  // Parse out the properties.
  dtfdt_parse_result_t status;
  int tok = consume_next_token(parse);
  while (tok == FDT_PROP) {
    uint32_t prop_len, prop_nameoff;
    if (consume_u32(parse, &prop_len) < 0) return -1;
    if (consume_u32(parse, &prop_nameoff) < 0) return -1;
    const char* prop_name =
        (const char*)(parse->fdt + parse->hdr->off_dt_strings + prop_nameoff);
    // TODO(aoates): validate name and value lengths.

    status = parse_int_prop(parse, prop_name, prop_len, "#address-cells",
                            &child_ctx.address_cells);
    if (status != DTFDT_OK) return status;
    status = parse_int_prop(parse, prop_name, prop_len, "#size-cells",
                            &child_ctx.size_cells);
    if (status != DTFDT_OK) return status;

    // Pass along the node property.
    parse->cbs->node_prop(prop_name, parse->fdtstruct + parse->pos, prop_len,
                          /* _parent_ context */ ctx, parse->cbarg);
    parse->pos += prop_len;
    parse->pos = align_up(parse->pos, sizeof(uint32_t));
    tok = consume_next_token(parse);
  }

  // Parse child nodes.  Now we use the child context constructed above.
  while (tok == FDT_BEGIN_NODE) {
    status = parse_node(parse, &child_ctx);
    if (status != DTFDT_OK) return status;
    tok = consume_next_token(parse);
  }

  // We must see an END_NODE token now.
  if (tok != FDT_END_NODE) {
    return DTFDT_BAD_TOKEN;
  }
  parse->cbs->node_end(node_name, parse->cbarg);
  return DTFDT_OK;
}

dtfdt_parse_result_t dtfdt_parse(const void* fdt, const fdt_header_t* hdr,
                                 const dtfdt_parse_cbs_t* cbs, void* cbarg) {
  if ((addr_t)fdt % sizeof(uint32_t) != 0) {
    return DTFDT_BAD_ALIGNMENT;
  }
  if (hdr->off_dt_struct % sizeof(uint32_t) != 0) {
    return DTFDT_BAD_ALIGNMENT;
  }
  fdt_parse_state_t parse;
  parse.fdt = fdt;
  parse.fdtstruct = fdt + hdr->off_dt_struct;
  parse.hdr = hdr;
  parse.pos = 0;
  parse.buflen = hdr->size_dt_struct;
  parse.cbs = cbs;
  parse.cbarg = cbarg;

  // We should start with a BEGIN_NODE for the root.
  int tok = consume_next_token(&parse);
  if (tok < 0) return tok;
  if (tok != FDT_BEGIN_NODE) return DTFDT_BAD_TOKEN;

  // TODO(aoates): consider validating the context is set properly on the root
  // node rather than just grabbing defaults.
  dtfdt_node_context_t root_ctx;
  node_context_defaults(&root_ctx);
  dtfdt_parse_result_t result = parse_node(&parse, &root_ctx);
  if (result != DTFDT_OK) return result;

  // We should end with an FDT_END.
  tok = consume_next_token(&parse);
  if (tok < 0) return tok;
  if (tok != FDT_END) return DTFDT_BAD_TOKEN;
  return DTFDT_OK;
}

typedef struct {
  dtfdt_sink_t sink;
  int indent;

  // Whether to put a spacer before the next node.
  bool space_next_node;
  char buf[100];
} fdt_print_state_t;

void fdt_printf(fdt_print_state_t* state, const char* fmt, ...)
    __attribute__((format(printf, 2, 3)));
void fdt_printf(fdt_print_state_t* state, const char* fmt, ...) {
  va_list args;
  va_start(args, fmt);
  kvsprintf(state->buf, fmt, args);
  va_end(args);

  state->sink(state->buf);
}

static void print_indent(const fdt_print_state_t* state) {
  for (int i = 0; i < state->indent * 2; ++i) {
    state->sink(" ");
  }
}

static uint64_t print_consume32(const char** buf) {
  uint64_t val = btoh32(*(const uint32_t*)*buf);
  *buf += sizeof(uint32_t);
  return val;
}

static uint64_t print_consume64(const char** buf) {
  uint64_t val = btoh64(*(const uint64_t*)*buf);
  *buf += sizeof(uint64_t);
  return val;
}

static uint64_t print_consume(int len_cells, const char** buf) {
  switch (len_cells) {
    case 1: return print_consume32(buf);
    case 2: return print_consume64(buf);
  }
  return 0xDEADBEEF;
}

// Attempt to print the value of a 'reg' property.
static bool try_print_reg(fdt_print_state_t* state,
                          const dtfdt_node_context_t* ctx, const char* buf,
                          uint32_t len) {
  const size_t reg_itm_sz =
      (ctx->address_cells + ctx->size_cells) * sizeof(uint32_t);
  // kprintf doesn't portably support 64-bit numbers on non-64-bit
  // architectures, so don't try and print them.
  const int max_cells = ARCH_IS_64_BIT ? 2 : 1;
  if (len % reg_itm_sz != 0 || ctx->address_cells < 1 ||
      ctx->address_cells > max_cells || ctx->size_cells < 0 ||
      ctx->size_cells > max_cells) {
    return false;
  }

  // We do the PRIxADDR dance to compile this on both 32- and 64-bit platforms.
  // On 32-bit platforms, address_cells will never be 2, so the round trip
  // through a uint64_t (while ineffecient) is harmless.
  for (size_t i = 0; i < len / reg_itm_sz; ++i) {
    uint64_t addr = print_consume(ctx->address_cells, &buf);
    if (ctx->size_cells == 0) {
      fdt_printf(state, "0x%" PRIxADDR, (addr_t)addr);
    } else {
      uint64_t len = print_consume(ctx->size_cells, &buf);
      fdt_printf(state, "<0x%" PRIxADDR " - 0x%" PRIxADDR "> ", (addr_t)addr,
                 (addr_t)(addr + len));
    }
  }
  return true;
}

static void print_propval(fdt_print_state_t* state,
                          const dtfdt_node_context_t* ctx, const char* propname,
                          const char* buf, uint32_t len) {
  // Try and guess the type.
  // TODO(aoates): look up the name in standard property table.
  if (len > 0 && buf[len - 1] == '\0') {
    // See if it's a string.
    // TODO(aoates): this handles stringlist wrong
    bool is_string = true;
    for (size_t i = 0; i < len - 1; ++i) {
      if (!kisprint(buf[i])) {
        is_string = false;
        break;
      }
    }
    if (is_string) {
      fdt_printf(state, "'%s' [string]", buf);
      return;
    }
  }

  if (len == sizeof(uint32_t)) {
    uint32_t val = btoh32(*(uint32_t*)buf);
    fdt_printf(state, "%u (0x%x) [u32]", val, val);
    return;
  }

  if (kstrcmp(propname, "reg") == 0) {
    if (try_print_reg(state, ctx, buf, len)) {
      return;
    }
  }

  fdt_printf(state, "<%d bytes>", len);
}

void print_node_begin_cb(const char* node_name,
                         const dtfdt_node_context_t* context, void* cbarg) {
  fdt_print_state_t* state = (fdt_print_state_t*)cbarg;
  if (state->space_next_node) {
    state->sink("\n");
  }
  print_indent(state);
  if (*node_name != '\0') {  // Don't print a space for root node.
    fdt_printf(state, "%s ", node_name);
  }
  fdt_printf(state, "{\n");

  state->indent++;
  state->space_next_node = false;
}

void print_node_end_cb(const char* node_name, void* cbarg) {
  fdt_print_state_t* state = (fdt_print_state_t*)cbarg;
  state->indent--;
  print_indent(state);
  state->sink("}\n");
  state->space_next_node = true;
}

void print_node_prop_cb(const char* prop_name, const void* prop_val,
                        size_t val_len, const dtfdt_node_context_t* context,
                        void* cbarg) {
  fdt_print_state_t* state = (fdt_print_state_t*)cbarg;
  print_indent(state);
  fdt_printf(state, "%s = ", prop_name);
  print_propval(state, context, prop_name, prop_val, val_len);
  state->sink("\n");
  state->space_next_node = true;
}

void dtfdt_print(const void* fdt, const fdt_header_t* hdr, bool print_header,
                 dtfdt_sink_t sink) {
  fdt_print_state_t state;
  state.sink = sink;
  state.indent = 0;
  state.space_next_node = false;

  if (print_header) {
    fdt_printf(&state, "FDT header:\n");
    fdt_printf(&state, " magic: 0x%x\n", hdr->magic);
    fdt_printf(&state, " totalsize: 0x%x\n", hdr->totalsize);
    fdt_printf(&state, " off_dt_struct: 0x%x\n", hdr->off_dt_struct);
    fdt_printf(&state, " off_dt_strings: 0x%x\n", hdr->off_dt_strings);
    fdt_printf(&state, " off_mem_rsvmap: 0x%x\n", hdr->off_mem_rsvmap);
    fdt_printf(&state, " version: 0x%x\n", hdr->version);
    fdt_printf(&state, " last_comp_version: 0x%x\n", hdr->last_comp_version);
    fdt_printf(&state, " boot_cpuid_phys: 0x%x\n", hdr->boot_cpuid_phys);
    fdt_printf(&state, " size_dt_strings: 0x%x\n", hdr->size_dt_strings);
    fdt_printf(&state, " size_dt_struct: 0x%x\n", hdr->size_dt_struct);

    fdt_printf(&state, "\nMemory reservation blocks:\n");
    const uint64_t* memres = (const uint64_t*)(fdt + hdr->off_mem_rsvmap);
    while (true) {
      // On 32-bit archs the upper 32 bits should be ignored, so cast them away.
      addr_t addr = (addr_t)btoh64(*(memres++));
      addr_t len = (addr_t)btoh64(*(memres++));
      if (addr == 0 && len == 0) break;
      fdt_printf(&state, "  0x%" PRIxADDR " - 0x%" PRIxADDR "\n", addr,
                 addr + len);
    }
    fdt_printf(&state, "\nFDT struct:\n");
  }

  dtfdt_parse_cbs_t cbs = {.node_begin = &print_node_begin_cb,
                           .node_end = &print_node_end_cb,
                           .node_prop = &print_node_prop_cb};
  dtfdt_parse_result_t parse_result = dtfdt_parse(fdt, hdr, &cbs, &state);
  if (parse_result != DTFDT_OK) {
    fdt_printf(&state, "<error: unable to parse DTB (%d)>\n", parse_result);
  }
}
