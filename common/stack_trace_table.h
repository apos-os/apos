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

// The stack trace table stores deduplicated stack traces, under the assumption
// that many stack traces that are sampled for a particular reason will be the
// same.
//
// Users record a stack trace with tracetbl_put(), which stores the stack trace
// (or finds it if already stored) and returns an id it can be referenced with.
// The client should call tracetbl_unref() when it no longer needs the stack
// trace, to allow that space to be reused.
#ifndef APOO_COMMON_STACK_TRACE_TABLE_H
#define APOO_COMMON_STACK_TRACE_TABLE_H

#include "common/types.h"

#define TRACETBL_MAX_TRACE_LEN 16

typedef short trace_id_t;

// Store the given stack trace, and return the id to fetch it later, or -error.
// Increments the stack trace's refcount.
trace_id_t tracetbl_put(const addr_t* trace, int len);

// Copy the stack trace referred to by the given id into |trace|.  Returns the
// stack trace's length, or -error.  |trace| must be at least
// TRACETBL_MAX_TRACE_LEN entries long.
int tracetbl_get(trace_id_t id, addr_t* trace);

// Decrement the stack trace referred to by id's refcount.  If the refcount goes
// to zero, the stacktrace slot may be reused (and any uses of that id are
// invalid).
void tracetbl_unref(trace_id_t id);

#endif
