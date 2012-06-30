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

#include <stdint.h>

#include "common/kassert.h"

#include "dev/video/vga.h"

struct video {
  uint8_t* videoram;
  uint32_t width;
  uint32_t height;
};

static video_t g_video;

video_t* video_get_default() {
  g_video.videoram = (uint8_t*)0xC00B8000;
  g_video.width = 80;
  g_video.height = 24;
  return &g_video;
}

uint32_t video_get_width(video_t* v) {
  return v->width;
}

uint32_t video_get_height(video_t* v) {
  return v->height;
}

void video_setc(video_t* v, uint32_t row, uint32_t col, uint8_t c) {
  if (col >= v->width || row >= v->height) {
    return;
  }
  v->videoram[2 * (row * v->width + col)] = c;
}

void video_clear(video_t* v) {
  uint32_t i;
  for (i = 0; i < v->width * v->height; ++i) {
    v->videoram[i*2] = ' ';
    v->videoram[i*2+1] = 0x07;
  }
}
