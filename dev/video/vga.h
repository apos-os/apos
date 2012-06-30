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

// Basic driver for built-in VGA display.  Probably wouldn't work on real
// hardware.
#ifndef DEV_VIDEO_VIDEO_H
#define DEV_VIDEO_VIDEO_H

#include <stdint.h>

typedef struct video video_t;

// Returns a video_t associated with the default display.
video_t* video_get_default();

// Return the width/height of the display.
uint32_t video_get_width(video_t* v);
uint32_t video_get_height(video_t* v);

// Sets the character at a given position on the display.
void video_setc(video_t* v, uint32_t row, uint32_t col, uint8_t c);

// Clears the display.
void video_clear(video_t* v);

#endif
