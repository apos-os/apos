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

#include "common/ascii.h"
#include "common/kassert.h"
#include "kmalloc.h"
#include "dev/char.h"
#include "dev/keyboard/keyboard.h"

static char NORMAL_ASCII_LOOKUP[];
static char SHIFT_ASCII_LOOKUP[];
static char CAPS_ASCII_LOOKUP[];

struct vkeyboard {
  // TODO(aoates): support control chars besides shift.
  uint8_t shift_down;
  uint8_t caps_down;
  uint8_t ctrl_down;
  uint8_t alt_down;
  char_sink_t handler;
  void* handler_arg;
};

vkeyboard_t* vkeyboard_create() {
  vkeyboard_t* kbd = (vkeyboard_t*)kmalloc(sizeof(vkeyboard_t));
  kbd->shift_down = kbd->caps_down = kbd->ctrl_down = kbd->alt_down = 0;
  kbd->handler = (char_sink_t)0;
  return kbd;
}

void vkeyboard_send_keycode(vkeyboard_t* kbd, uint8_t code, uint8_t up) {
  KASSERT(code <= KEY_MAX_KEY);

  if (code == KEY_L_SHFT || code == KEY_R_SHFT) {
    kbd->shift_down = !up;
  } else if (code == KEY_CAPS) {
    kbd->caps_down = !up;
  } else if (code == KEY_L_CTRL || code == KEY_R_CTRL) {
    kbd->ctrl_down = !up;
  } else if (code == KEY_L_ALT || code == KEY_R_ALT) {
    kbd->alt_down = !up;
  } else if (!up) {
    char out = '\0';
    if (kbd->shift_down) {
      out = SHIFT_ASCII_LOOKUP[code];
    } else if (kbd->caps_down) {
      out = CAPS_ASCII_LOOKUP[code];
    } else {
      out = NORMAL_ASCII_LOOKUP[code];
    }
    // TODO(aoates): figure out a more elegent way to do this.
    if ((out == 'd' || out == 'D') && kbd->ctrl_down) {
      out = ASCII_EOT;
    }
    if (kbd->handler || out != '\0') {
      kbd->handler(kbd->handler_arg, out);
    }
  }
}

void vkeyboard_set_handler(vkeyboard_t* kbd, char_sink_t handler, void* arg) {
  kbd->handler = handler;
  kbd->handler_arg = arg;
}

// Maps from keycode to ASCII.
static char NORMAL_ASCII_LOOKUP[] = {
  '\0', // NONE
  '0', // KEY_0
  '1', // KEY_1
  '2', // KEY_2
  '3', // KEY_3
  '4', // KEY_4
  '5', // KEY_5
  '6', // KEY_6
  '7', // KEY_7
  '8', // KEY_8
  '9', // KEY_9
  'a', // KEY_A
  'b', // KEY_B
  'c', // KEY_C
  'd', // KEY_D
  'e', // KEY_E
  'f', // KEY_F
  'g', // KEY_G
  'h', // KEY_H
  'i', // KEY_I
  'j', // KEY_J
  'k', // KEY_K
  'l', // KEY_L
  'm', // KEY_M
  'n', // KEY_N
  'o', // KEY_O
  'p', // KEY_P
  'q', // KEY_Q
  'r', // KEY_R
  's', // KEY_S
  't', // KEY_T
  'u', // KEY_U
  'v', // KEY_V
  'w', // KEY_W
  'x', // KEY_X
  'y', // KEY_Y
  'z', // KEY_Z
  '\0', // KEY_L_ALT
  '\0', // KEY_R_ALT
  '\0', // KEY_L_ARROW
  '\0', // KEY_R_ARROW
  '\0', // KEY_L_CTRL
  '\0', // KEY_R_CTRL
  '\0', // KEY_L_GUI
  '\0', // KEY_R_GUI
  '\0', // KEY_L_SHFT
  '\0', // KEY_R_SHFT
  '\0', // KEY_U_ARROW
  '\0', // KEY_D_ARROW
  '\0', // KEY_KP_STAR
  '\0', // KEY_KP_PLUS
  '\0', // KEY_KP_DASH
  '\0', // KEY_KP_PERIOD
  '\0', // KEY_KP_SLASH
  '\0', // KEY_KP_0
  '\0', // KEY_KP_1
  '\0', // KEY_KP_2
  '\0', // KEY_KP_3
  '\0', // KEY_KP_4
  '\0', // KEY_KP_5
  '\0', // KEY_KP_6
  '\0', // KEY_KP_7
  '\0', // KEY_KP_8
  '\0', // KEY_KP_9
  '\n', // KEY_KP_EN
  '\0', // KEY_F1
  '\0', // KEY_F2
  '\0', // KEY_F3
  '\0', // KEY_F4
  '\0', // KEY_F5
  '\0', // KEY_F6
  '\0', // KEY_F7
  '\0', // KEY_F8
  '\0', // KEY_F9
  '\0', // KEY_F10
  '\0', // KEY_F11
  '\0', // KEY_F12
  '\'', // KEY_QUOTE
  ',', // KEY_COMMA
  '-', // KEY_DASH
  '.', // KEY_PERIOD
  '/', // KEY_SLASH
  ';', // KEY_SEMICOLON
  '=', // KEY_EQUALS
  '\0', // KEY_APPS
  '\b', // KEY_BKSP
  '\0', // KEY_CAPS
  '\177', // KEY_DELETE
  '\0', // KEY_END
  '\n', // KEY_ENTER
  '\033', // KEY_ESC
  '\0', // KEY_HOME
  '\0', // KEY_INSERT
  '\0', // KEY_NUM
  '\0', // KEY_PG_DN
  '\0', // KEY_PG_UP
  '\0', // KEY_SCROLL
  ' ', // KEY_SPACE
  '\t', // KEY_TAB
  '[', // KEY_LBRACKET
  '\\', // KEY_BSLASH
  ']', // KEY_RBRACKET
  '`', // KEY_BACKTICK
};

// Lookup when shift is down.
static char SHIFT_ASCII_LOOKUP[] = {
  '\0', // NONE
  ')', // KEY_0
  '!', // KEY_1
  '@', // KEY_2
  '#', // KEY_3
  '$', // KEY_4
  '%', // KEY_5
  '^', // KEY_6
  '&', // KEY_7
  '*', // KEY_8
  '(', // KEY_9
  'A', // KEY_A
  'B', // KEY_B
  'C', // KEY_C
  'D', // KEY_D
  'E', // KEY_E
  'F', // KEY_F
  'G', // KEY_G
  'H', // KEY_H
  'I', // KEY_I
  'J', // KEY_J
  'K', // KEY_K
  'L', // KEY_L
  'M', // KEY_M
  'N', // KEY_N
  'O', // KEY_O
  'P', // KEY_P
  'Q', // KEY_Q
  'R', // KEY_R
  'S', // KEY_S
  'T', // KEY_T
  'U', // KEY_U
  'V', // KEY_V
  'W', // KEY_W
  'X', // KEY_X
  'Y', // KEY_Y
  'Z', // KEY_Z
  '\0', // KEY_L_ALT
  '\0', // KEY_R_ALT
  '\0', // KEY_L_ARROW
  '\0', // KEY_R_ARROW
  '\0', // KEY_L_CTRL
  '\0', // KEY_R_CTRL
  '\0', // KEY_L_GUI
  '\0', // KEY_R_GUI
  '\0', // KEY_L_SHFT
  '\0', // KEY_R_SHFT
  '\0', // KEY_U_ARROW
  '\0', // KEY_D_ARROW
  '\0', // KEY_KP_STAR
  '\0', // KEY_KP_PLUS
  '\0', // KEY_KP_DASH
  '\0', // KEY_KP_PERIOD
  '\0', // KEY_KP_SLASH
  '\0', // KEY_KP_0
  '\0', // KEY_KP_1
  '\0', // KEY_KP_2
  '\0', // KEY_KP_3
  '\0', // KEY_KP_4
  '\0', // KEY_KP_5
  '\0', // KEY_KP_6
  '\0', // KEY_KP_7
  '\0', // KEY_KP_8
  '\0', // KEY_KP_9
  '\n', // KEY_KP_EN
  '\0', // KEY_F1
  '\0', // KEY_F2
  '\0', // KEY_F3
  '\0', // KEY_F4
  '\0', // KEY_F5
  '\0', // KEY_F6
  '\0', // KEY_F7
  '\0', // KEY_F8
  '\0', // KEY_F9
  '\0', // KEY_F10
  '\0', // KEY_F11
  '\0', // KEY_F12
  '"', // KEY_QUOTE
  '<', // KEY_COMMA
  '_', // KEY_DASH
  '>', // KEY_PERIOD
  '?', // KEY_SLASH
  ':', // KEY_SEMICOLON
  '+', // KEY_EQUALS
  '\0', // KEY_APPS
  '\b', // KEY_BKSP
  '\0', // KEY_CAPS
  '\177', // KEY_DELETE
  '\0', // KEY_END
  '\n', // KEY_ENTER
  '\033', // KEY_ESC
  '\0', // KEY_HOME
  '\0', // KEY_INSERT
  '\0', // KEY_NUM
  '\0', // KEY_PG_DN
  '\0', // KEY_PG_UP
  '\0', // KEY_SCROLL
  ' ', // KEY_SPACE
  '\t', // KEY_TAB
  '{', // KEY_LBRACKET
  '|', // KEY_BSLASH
  '}', // KEY_RBRACKET
  '~', // KEY_BACKTICK
};

static char CAPS_ASCII_LOOKUP[] = {
  '\0', // NONE
  '0', // KEY_0
  '1', // KEY_1
  '2', // KEY_2
  '3', // KEY_3
  '4', // KEY_4
  '5', // KEY_5
  '6', // KEY_6
  '7', // KEY_7
  '8', // KEY_8
  '9', // KEY_9
  'A', // KEY_A
  'B', // KEY_B
  'C', // KEY_C
  'D', // KEY_D
  'E', // KEY_E
  'F', // KEY_F
  'G', // KEY_G
  'H', // KEY_H
  'I', // KEY_I
  'J', // KEY_J
  'K', // KEY_K
  'L', // KEY_L
  'M', // KEY_M
  'N', // KEY_N
  'O', // KEY_O
  'P', // KEY_P
  'Q', // KEY_Q
  'R', // KEY_R
  'S', // KEY_S
  'T', // KEY_T
  'U', // KEY_U
  'V', // KEY_V
  'W', // KEY_W
  'X', // KEY_X
  'Y', // KEY_Y
  'Z', // KEY_Z
  '\0', // KEY_L_ALT
  '\0', // KEY_R_ALT
  '\0', // KEY_L_ARROW
  '\0', // KEY_R_ARROW
  '\0', // KEY_L_CTRL
  '\0', // KEY_R_CTRL
  '\0', // KEY_L_GUI
  '\0', // KEY_R_GUI
  '\0', // KEY_L_SHFT
  '\0', // KEY_R_SHFT
  '\0', // KEY_U_ARROW
  '\0', // KEY_D_ARROW
  '\0', // KEY_KP_STAR
  '\0', // KEY_KP_PLUS
  '\0', // KEY_KP_DASH
  '\0', // KEY_KP_PERIOD
  '\0', // KEY_KP_SLASH
  '\0', // KEY_KP_0
  '\0', // KEY_KP_1
  '\0', // KEY_KP_2
  '\0', // KEY_KP_3
  '\0', // KEY_KP_4
  '\0', // KEY_KP_5
  '\0', // KEY_KP_6
  '\0', // KEY_KP_7
  '\0', // KEY_KP_8
  '\0', // KEY_KP_9
  '\n', // KEY_KP_EN
  '\0', // KEY_F1
  '\0', // KEY_F2
  '\0', // KEY_F3
  '\0', // KEY_F4
  '\0', // KEY_F5
  '\0', // KEY_F6
  '\0', // KEY_F7
  '\0', // KEY_F8
  '\0', // KEY_F9
  '\0', // KEY_F10
  '\0', // KEY_F11
  '\0', // KEY_F12
  '\'', // KEY_QUOTE
  ',', // KEY_COMMA
  '-', // KEY_DASH
  '.', // KEY_PERIOD
  '/', // KEY_SLASH
  ';', // KEY_SEMICOLON
  '=', // KEY_EQUALS
  '\0', // KEY_APPS
  '\b', // KEY_BKSP
  '\0', // KEY_CAPS
  '\177', // KEY_DELETE
  '\0', // KEY_END
  '\n', // KEY_ENTER
  '\033', // KEY_ESC
  '\0', // KEY_HOME
  '\0', // KEY_INSERT
  '\0', // KEY_NUM
  '\0', // KEY_PG_DN
  '\0', // KEY_PG_UP
  '\0', // KEY_SCROLL
  ' ', // KEY_SPACE
  '\t', // KEY_TAB
  '[', // KEY_LBRACKET
  '\\', // KEY_BSLASH
  ']', // KEY_RBRACKET
  '`', // KEY_BACKTICK
};
