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

// Interface for charater devices.
#ifndef APOO_DEV_CHAR_DEV_H
#define APOO_DEV_CHAR_DEV_H

#include <stdint.h>

// A char_sink_t is a function accepting an opaque arg and a character to be
// processed.
//
// Generally, character sources (like keyboards and line disciplines) will be
// configured with a char_sink_t to call when a character is available (and the
// arg to pass to that sink).
typedef void (*char_sink_t)(void*, char);

// A single character device.
struct char_dev {
  // Read up to len bytes from the device into the given buffer.  Blocks until
  // the read is complete.  If no bytes are available, blocks until some can be
  // read.
  //
  // Returns the number of bytes read on success, 0 for EOF, or -error on error.
  int (*read)(struct char_dev* dev, void* buf, uint32_t len);

  // Write up to len bytes to the device. Blocks until the write is complete.
  //
  // Returns the number of bytes written on success, or -error on error.
  int (*write)(struct char_dev* dev, const void* buf, uint32_t len);

  // Device-specific private data.
  void* dev_data;
};
typedef struct char_dev char_dev_t;

#endif
