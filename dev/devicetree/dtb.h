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
#ifndef APOO_DEV_DEVICETREE_DTB_H
#define APOO_DEV_DEVICETREE_DTB_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define DTFDT_VERSION 17

// Header of a DTB blob.
typedef struct {
  uint32_t magic;
  uint32_t totalsize;
  uint32_t off_dt_struct;
  uint32_t off_dt_strings;
  uint32_t off_mem_rsvmap;
  uint32_t version;
  uint32_t last_comp_version;
  uint32_t boot_cpuid_phys;
  uint32_t size_dt_strings;
  uint32_t size_dt_struct;
} __attribute__((packed)) fdt_header_t;

typedef fdt_header_t fdt_header_t_bige;

// Reads the header at the given address and does basic validation.  If OK,
// returns zero and copies the header data (in host endian) into the given
// header struct.
int dtfdt_validate(const void* buf, fdt_header_t* header);

typedef void(*dtfdt_sink_t)(const char*);
// Prints the given FDT (in DTB form), using the given function as a sink.
int dtfdt_print(const void* fdt, bool print_header, dtfdt_sink_t sink);

// Context for a parsed node, with the #address-cells and #size-cells properties
// of the node's _parent_.
typedef struct {
  int address_cells;
  int size_cells;
} dtfdt_node_context_t;

// If any of these callbacks returns false, parsing will stop and DTFDT_STOPPED
// will be returned.
typedef bool (*dtfdt_node_begin_cb)(const char* node_name,
                                    const dtfdt_node_context_t* context,
                                    void* cbarg);
typedef bool (*dtfdt_node_end_cb)(const char* node_name, void* cbarg);
typedef bool (*dtfdt_node_prop_cb)(const char* prop_name, const void* prop_val,
                                   size_t val_len,
                                   const dtfdt_node_context_t* context,
                                   void* cbarg);

// Callbacks for parsing.
typedef struct {
  // Called when a node is begun.
  dtfdt_node_begin_cb node_begin;
  // Called when a node finishes.
  dtfdt_node_end_cb node_end;
  // Called for each property of a node.
  dtfdt_node_prop_cb node_prop;
} dtfdt_parse_cbs_t;

// Parsing results.
typedef enum {
  DTFDT_OK = 0,              // The parse was succesful.
  DTFDT_STOPPED = -1,        // A callback indicated the parse should stop.
  DTFDT_BAD_HEADER = -2,     // The FDT header was bad.
  DTFDT_BUF_TOO_SHORT = -3,  // The buffer is too short.
  DTFDT_BAD_TOKEN = -4,      // Invalid token seen.
  DTFDT_BAD_NAME = -5,       // Invalid node or property name.
  DTFDT_BAD_ALIGNMENT = -6,
  DTFDT_BAD_PROPERTY = -7,
} dtfdt_parse_result_t;

// Parse the given DTB.  Doesn't dynamically allocate any memory, so is
// safe to use during boot.  Property values are passed as uninterpreted blobs
// (in big-endian order).  Returns 0 (DTFDT_OK) or an error.
dtfdt_parse_result_t dtfdt_parse(const void* fdt, const dtfdt_parse_cbs_t* cbs,
                                 void* cbarg);

#endif
