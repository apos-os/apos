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

#ifndef APOO_DEV_VIDEO_ANSI_ESCAPE_H
#define APOO_DEV_VIDEO_ANSI_ESCAPE_H

#include <stddef.h>

#include "dev/video/vga.h"

#define ANSI_MAX_ESCAPE_SEQUENCE_LEN 20
#define ANSI_MAX_ESCAPE_CODES 10

// Return codes for parse_ansi_escape().
#define ANSI_SUCCESS 0
#define ANSI_PENDING 1
#define ANSI_INVALID 2

// A parsed ANSI escape sequence, consisting of a sequence of codes and a final
// letter.  If a particular code is missing, the corresponding entry will be -1.
typedef struct {
  int codes[ANSI_MAX_ESCAPE_CODES];
  int num_codes;
  char final_letter;
} ansi_seq_t;

// Attempt to parse an ANSI escape sequence from the given buffer.  Returns
// ANSI_SUCCESS if the buffer contains a valid and parseable escape sequence.
// Returns ANSI_PENDING if the buffer contains the prefix of a valid escape
// sequence (i.e. we haven't seen the whole thing).  Returns ANSI_INVALID if the
// given escape sequence is invalid or unsupported.
//
// If the escape sequence is valid and complete, *seq is updated.
int parse_ansi_escape(const char* buf, size_t len, ansi_seq_t* seq);

// Apply the given (parsed) ANSI escaped sequence to the given video_attr_t, if
// the sequence is an SGR sequence.
int apply_ansi_color(const ansi_seq_t* seq, video_attr_t* attr);

// Attempt to parse an ANSI escape sequence from the given buffer.  If it is
// valid and complete, apply it to *attr.
// TODO(aoates): update all callers to this to use the above functions.
int apply_ansi_escape(const char* buf, size_t len, video_attr_t* attr);

#endif
