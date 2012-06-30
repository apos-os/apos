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

#include "dev/keyboard/keyboard.h"
#include "dev/keyboard/ps2_scancodes.h"

// Table to translate from single-digit scan codes to the universal key code.
static uint8_t NORMAL_TRANSLATION_TABLE[] = {
  NONE, // 0x0
  KEY_F9, // 0x01
  NONE, // 0x2
  KEY_F5, // 0x03
  KEY_F3, // 0x04
  KEY_F1, // 0x05
  KEY_F2, // 0x06
  KEY_F12, // 0x07
  NONE, // 0x8
  KEY_F10, // 0x09
  KEY_F8, // 0x0A
  KEY_F6, // 0x0B
  KEY_F4, // 0x0C
  KEY_TAB, // 0x0D
  KEY_BACKTICK, // 0x0E
  NONE, // 0xf
  NONE, // 0x10
  KEY_L_ALT, // 0x11
  KEY_L_SHFT, // 0x12
  NONE, // 0x13
  KEY_L_CTRL, // 0x14
  KEY_Q, // 0x15
  KEY_1, // 0x16
  NONE, // 0x17
  NONE, // 0x18
  NONE, // 0x19
  KEY_Z, // 0x1A
  KEY_S, // 0x1B
  KEY_A, // 0x1C
  KEY_W, // 0x1D
  KEY_2, // 0x1E
  NONE, // 0x1f
  NONE, // 0x20
  KEY_C, // 0x21
  KEY_X, // 0x22
  KEY_D, // 0x23
  KEY_E, // 0x24
  KEY_4, // 0x25
  KEY_3, // 0x26
  NONE, // 0x27
  NONE, // 0x28
  KEY_SPACE, // 0x29
  KEY_V, // 0x2A
  KEY_F, // 0x2B
  KEY_T, // 0x2C
  KEY_R, // 0x2D
  KEY_5, // 0x2E
  NONE, // 0x2f
  NONE, // 0x30
  KEY_N, // 0x31
  KEY_B, // 0x32
  KEY_H, // 0x33
  KEY_G, // 0x34
  KEY_Y, // 0x35
  KEY_6, // 0x36
  NONE, // 0x37
  NONE, // 0x38
  NONE, // 0x39
  KEY_M, // 0x3A
  KEY_J, // 0x3B
  KEY_U, // 0x3C
  KEY_7, // 0x3D
  KEY_8, // 0x3E
  NONE, // 0x3f
  NONE, // 0x40
  KEY_COMMA, // 0x41
  KEY_K, // 0x42
  KEY_I, // 0x43
  KEY_O, // 0x44
  KEY_0, // 0x45
  KEY_9, // 0x46
  NONE, // 0x47
  NONE, // 0x48
  KEY_PERIOD, // 0x49
  KEY_SLASH, // 0x4A
  KEY_L, // 0x4B
  KEY_SEMICOLON, // 0x4C
  KEY_P, // 0x4D
  KEY_DASH, // 0x4E
  NONE, // 0x4f
  NONE, // 0x50
  NONE, // 0x51
  KEY_QUOTE, // 0x52
  NONE, // 0x53
  KEY_LBRACKET, // 0x54
  KEY_EQUALS, // 0x55
  NONE, // 0x56
  NONE, // 0x57
  KEY_CAPS, // 0x58
  KEY_R_SHFT, // 0x59
  KEY_ENTER, // 0x5A
  KEY_LBRACKET, // 0x5B
  NONE, // 0x5c
  KEY_BSLASH, // 0x5D
  NONE, // 0x5e
  NONE, // 0x5f
  NONE, // 0x60
  NONE, // 0x61
  NONE, // 0x62
  NONE, // 0x63
  NONE, // 0x64
  NONE, // 0x65
  KEY_BKSP, // 0x66
  NONE, // 0x67
  NONE, // 0x68
  KEY_KP_1, // 0x69
  NONE, // 0x6a
  KEY_KP_4, // 0x6B
  KEY_KP_7, // 0x6C
  NONE, // 0x6d
  NONE, // 0x6e
  NONE, // 0x6f
  KEY_KP_0, // 0x70
  KEY_KP_PERIOD, // 0x71
  KEY_KP_2, // 0x72
  KEY_KP_5, // 0x73
  KEY_KP_6, // 0x74
  KEY_KP_8, // 0x75
  KEY_ESC, // 0x76
  KEY_NUM, // 0x77
  KEY_F11, // 0x78
  KEY_KP_PLUS, // 0x79
  KEY_KP_3, // 0x7A
  KEY_KP_DASH, // 0x7B
  KEY_KP_STAR, // 0x7C
  KEY_KP_9, // 0x7D
  KEY_SCROLL, // 0x7E
  NONE, // 0x7f
  NONE, // 0x80
  NONE, // 0x81
  NONE, // 0x82
  KEY_F7, // 0x83
};
#define MAX_NORMAL_SCANCODE 0x83

// Table to translate from extended scan codes to the universal key code.
static uint8_t EXTENDED_TRANSLATION_TABLE[] = {
  NONE, // 0x0
  NONE, // 0x1
  NONE, // 0x2
  NONE, // 0x3
  NONE, // 0x4
  NONE, // 0x5
  NONE, // 0x6
  NONE, // 0x7
  NONE, // 0x8
  NONE, // 0x9
  NONE, // 0xa
  NONE, // 0xb
  NONE, // 0xc
  NONE, // 0xd
  NONE, // 0xe
  NONE, // 0xf
  NONE, // 0x10
  KEY_R_ALT, // 0x11
  NONE, // 0x12
  NONE, // 0x13
  KEY_R_CTRL, // 0x14
  NONE, // 0x15
  NONE, // 0x16
  NONE, // 0x17
  NONE, // 0x18
  NONE, // 0x19
  NONE, // 0x1a
  NONE, // 0x1b
  NONE, // 0x1c
  NONE, // 0x1d
  NONE, // 0x1e
  KEY_L_GUI, // 0x1F
  NONE, // 0x20
  NONE, // 0x21
  NONE, // 0x22
  NONE, // 0x23
  NONE, // 0x24
  NONE, // 0x25
  NONE, // 0x26
  KEY_R_GUI, // 0x27
  NONE, // 0x28
  NONE, // 0x29
  NONE, // 0x2a
  NONE, // 0x2b
  NONE, // 0x2c
  NONE, // 0x2d
  NONE, // 0x2e
  KEY_APPS, // 0x2F
  NONE, // 0x30
  NONE, // 0x31
  NONE, // 0x32
  NONE, // 0x33
  NONE, // 0x34
  NONE, // 0x35
  NONE, // 0x36
  NONE, // 0x37
  NONE, // 0x38
  NONE, // 0x39
  NONE, // 0x3a
  NONE, // 0x3b
  NONE, // 0x3c
  NONE, // 0x3d
  NONE, // 0x3e
  NONE, // 0x3f
  NONE, // 0x40
  NONE, // 0x41
  NONE, // 0x42
  NONE, // 0x43
  NONE, // 0x44
  NONE, // 0x45
  NONE, // 0x46
  NONE, // 0x47
  NONE, // 0x48
  NONE, // 0x49
  KEY_KP_SLASH, // 0x4A
  NONE, // 0x4b
  NONE, // 0x4c
  NONE, // 0x4d
  NONE, // 0x4e
  NONE, // 0x4f
  NONE, // 0x50
  NONE, // 0x51
  NONE, // 0x52
  NONE, // 0x53
  NONE, // 0x54
  NONE, // 0x55
  NONE, // 0x56
  NONE, // 0x57
  NONE, // 0x58
  NONE, // 0x59
  KEY_KP_EN, // 0x5A
  NONE, // 0x5b
  NONE, // 0x5c
  NONE, // 0x5d
  NONE, // 0x5e
  NONE, // 0x5f
  NONE, // 0x60
  NONE, // 0x61
  NONE, // 0x62
  NONE, // 0x63
  NONE, // 0x64
  NONE, // 0x65
  NONE, // 0x66
  NONE, // 0x67
  NONE, // 0x68
  KEY_END, // 0x69
  NONE, // 0x6a
  KEY_L_ARROW, // 0x6B
  KEY_HOME, // 0x6C
  NONE, // 0x6d
  NONE, // 0x6e
  NONE, // 0x6f
  KEY_INSERT, // 0x70
  KEY_DELETE, // 0x71
  KEY_D_ARROW, // 0x72
  NONE, // 0x73
  KEY_R_ARROW, // 0x74
  KEY_U_ARROW, // 0x75
  NONE, // 0x76
  NONE, // 0x77
  NONE, // 0x78
  NONE, // 0x79
  KEY_PG_DN, // 0x7A
  NONE, // 0x7b
  NONE, // 0x7c
  KEY_PG_UP, // 0x7D
};
#define MAX_EXTENDED_SCANCODE 0x7D

uint32_t ps2_convert_scancode(uint8_t scancode, uint8_t is_extended) {
  if ((!is_extended && scancode > MAX_NORMAL_SCANCODE) ||
      (is_extended && scancode > MAX_EXTENDED_SCANCODE)) {
    return NONE;
  }
  if (!is_extended) {
    return NORMAL_TRANSLATION_TABLE[scancode];
  } else {
    return EXTENDED_TRANSLATION_TABLE[scancode];
  }
}
