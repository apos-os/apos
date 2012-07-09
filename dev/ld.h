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

// Basic terminal line discipline.
//
// Attaches to a character source and sink, and is responsible for processing
// characters from the source (e.g. a keyboard), echoing them to the sink, and
// providing read/write buffers for use by callers who want cooked line data.
#ifndef APOO_LINE_DISCIPLINE_H
#define APOO_LINE_DISCIPLINE_H

#include "dev/char.h"

struct ld;
typedef struct ld ld_t;

// Allocate and initialize a new line discipline.
ld_t* ld_create();

// **** Functions for connecting the ld to the terminal ****
// Provide a character from the keyboard (or other source) to the given ld.
//
// This sink WILL NOT block (as it is generally expected to be run from an
// interrupt handler).
void ld_provide(ld_t* l, char c);

// char_sink_t version of the above.
static inline void ld_provide_sink(void* arg, char c) {
  ld_provide((ld_t*)arg, c);
}

// Set the character sink (e.g. vterm) for the line discipline.  The ld will
// send characters to the sink for (a) echoing input, and (b) displaying written
// bytes.
//
// The character sink MAY block.
void ld_set_sink(ld_t* l, char_sink_t sink, void* arg);

// **** Functions for reading and writing to the ld from client code ****
// Reads from the ld into buf, up to n characters.  Returns the number of bytes
// read, or zero if an end-of-stream was encountered.
//
// If there is no data available, blocks until data becomes available.
int ld_read(ld_t* l, char* buf, int n);

// Write n characters from buf to the ld's output.  Returns the number of
// characters written.
int ld_write(ld_t* l, char* buf, int n);

#endif
