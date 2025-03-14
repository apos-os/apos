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

#include "dev/video/ansi_escape.h"

#include "common/kstring.h"

const uint8_t kAnsiToVgaCode[] = {
  VGA_BLACK,
  VGA_RED,
  VGA_GREEN,
  VGA_YELLOW,
  VGA_BLUE,
  VGA_MAGENTA,
  VGA_CYAN,
  VGA_WHITE,
};

int parse_ansi_escape(const char* buf, size_t len, ansi_seq_t* seq) {
  if (len >= 1 && buf[0] != '\x1b') return ANSI_INVALID;
  if (len >= 2 && buf[1] != '[') return ANSI_INVALID;
  if (len < 3) return ANSI_PENDING;
  if (len > ANSI_MAX_ESCAPE_SEQUENCE_LEN) return ANSI_INVALID;
  buf += 2;
  len -= 2;

  // Make a pass through to verify the sequence is well-formed.
  size_t i = 0;
  for (i = 0; i < len - 1; ++i) {
    if (i == 0 && buf[i] == '?') continue;
    if (!kisdigit((int)buf[i]) && buf[i] != ';')
      return ANSI_INVALID;
  }
  if (!kisalnum((int)buf[len - 1]) && buf[len - 1] != ';' &&
      !(i == 0 && buf[len - 1] == '?'))
    return ANSI_INVALID;
  if (!kisalpha((int)buf[len-1]))
    return (len < ANSI_MAX_ESCAPE_SEQUENCE_LEN - 2) ? ANSI_PENDING :
        ANSI_INVALID;

  // We have a full escape code.
  seq->final_letter = buf[len-1];
  len--;

  if (len > 0 && buf[0] == '?') {
    seq->priv = true;
    buf++;
    len--;
  } else {
    seq->priv = false;
  }

  i = 0;
  seq->num_codes = 0;
  char num[ANSI_MAX_ESCAPE_SEQUENCE_LEN];
  // Loop until we hit the end.  The second condition catches a trailing ';'
  // (otherwise the final code (-1) is skipped).
  while (i < len || (i == len && i > 0)) {
    size_t numidx = 0;
    while (buf[i] >= '0' && buf[i] <= '9' && i < len) {
      num[numidx++] = buf[i++];
    }
    if (numidx > 3) return ANSI_INVALID;
    num[numidx] = '\0';
    if (i < len && buf[i] != ';') return ANSI_INVALID;
    i++;
    seq->codes[seq->num_codes++] = (numidx > 0) ? katoi(num) : -1;
  }

  return ANSI_SUCCESS;
}

int apply_ansi_color(const ansi_seq_t* seq, video_attr_t* attr) {
  if (seq->final_letter != 'm') return ANSI_INVALID;

  for (int i = 0; i < seq->num_codes; ++i) {
    int code = seq->codes[i];
    if (code >= 30 && code <= 37) {
      const uint8_t bright = video_attr_fg(*attr) & VGA_BRIGHT;
      *attr = video_mk_attr(kAnsiToVgaCode[code - 30] | bright,
                            video_attr_bg(*attr));
    } else if (code == 39) {
      *attr = video_mk_attr(video_attr_fg(VGA_DEFAULT_ATTR),
                            video_attr_bg(*attr));
    } else if (code >= 40 && code <= 47) {
      const uint8_t bright = video_attr_bg(*attr) & VGA_BRIGHT;
      *attr = video_mk_attr(video_attr_fg(*attr),
                            kAnsiToVgaCode[code - 40] | bright);
    } else if (code == 49) {
      *attr = video_mk_attr(video_attr_fg(*attr),
                            video_attr_bg(VGA_DEFAULT_ATTR));
    } else if (code == 7) {
      *attr = video_mk_attr(video_attr_bg(*attr), video_attr_fg(*attr));
    } else if (code == 0) {
      *attr = VGA_DEFAULT_ATTR;
    } else if (code == 1) {
      *attr = video_mk_attr(video_attr_fg(*attr) | VGA_BRIGHT,
                            video_attr_bg(*attr) | VGA_BRIGHT);
    }
  }

  return ANSI_SUCCESS;
}

int apply_ansi_escape(const char* buf, size_t len, video_attr_t* attr) {
  ansi_seq_t seq;
  int result = parse_ansi_escape(buf, len, &seq);
  if (result != ANSI_SUCCESS) return result;

  return apply_ansi_color(&seq, attr);
}
