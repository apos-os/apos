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

#include "dev/dev.h"

struct ld;
typedef struct ld ld_t;
struct ktermios;

// Allocate and initialize a new line discipline, with an internal buffer of the
// given size.
ld_t* ld_create(int buf_size);

// Free and ld_t created with ld_create().  You must call this instead of
// freeing the ld_t directly or you will leak memory.
void ld_destroy(ld_t* l);

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

// Set the TTY associated with the line discipline.  The TTY will be used to
// send signals, e.g. on ctrl-C, etc.
//
// The TTY must outlive the line discipline.
void ld_set_tty(ld_t* l, apos_dev_t tty);
apos_dev_t ld_get_tty(const ld_t* l);

// **** Functions for reading and writing to the ld from client code ****
// Reads from the ld into buf, up to n characters.  Returns the number of bytes
// read, or zero if an end-of-stream was encountered.
//
// If there is no data available, blocks until data becomes available.
int ld_read(ld_t* l, char* buf, int n, int flags);

// Write n characters from buf to the ld's output.  Returns the number of
// characters written.
int ld_write(ld_t* l, const char* buf, int n);

// Initialize a char_dev_t for the given ld.
void ld_init_char_dev(ld_t* l, char_dev_t* dev);

// Return the ld's terminal attributes.
void ld_get_termios(const ld_t* l, struct ktermios* t);

// Set the ld's terminal attributes.
int ld_set_termios(ld_t* l, int optional_actions, const struct ktermios* t);

// Block until all the output from the ld is flushed.  This is currently a
// no-op.
int ld_drain(ld_t* l);

// Flush the input and/or output of the given ld.  queue_selector must be one of
// {TCIFLUSH, TCOFLUSH, TCIOFLUSH}.
int ld_flush(ld_t* l, int queue_selector);

#endif
