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

// Return codes for parse_ansi_escape().
#define ANSI_SUCCESS 0
#define ANSI_PENDING 1
#define ANSI_INVALID 2

// Attempt to parse an ANSI escape sequence from the given buffer.  Returns
// ANSI_SUCCESS if the buffer contains a valid and parseable escape sequence.
// Returns ANSI_PENDING if the buffer contains the prefix of a valid escape
// sequence (i.e. we haven't seen the whole thing).  Returns ANSI_INVALID if the
// given escape sequence is invalid or unsupported.
//
// If the escape sequence is valid and complete, *attr is updated appropriately.
int parse_ansi_escape(const char* buf, size_t len, video_attr_t* attr);

#endif
