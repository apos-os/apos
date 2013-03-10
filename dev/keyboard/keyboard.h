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

// Code for tracking keyboard state and generating an ASCII stream from a
// stream of keyboard events.  Hardward drivers (like PS/2) are attached to a
// particular "virtual keyboard", which receives raw key events and translates
// that into ASCII output for consumption (e.g. by a line discipline).
#ifndef APOO_KEYBOARD_KEYBOARD_H
#define APOO_KEYBOARD_KEYBOARD_H

#include <stdint.h>

#include "dev/char_dev.h"

// Raw key codes.  Provided by hardward drivers.
#define NONE 0
#define KEY_0 1
#define KEY_1 2
#define KEY_2 3
#define KEY_3 4
#define KEY_4 5
#define KEY_5 6
#define KEY_6 7
#define KEY_7 8
#define KEY_8 9
#define KEY_9 10
#define KEY_A 11
#define KEY_B 12
#define KEY_C 13
#define KEY_D 14
#define KEY_E 15
#define KEY_F 16
#define KEY_G 17
#define KEY_H 18
#define KEY_I 19
#define KEY_J 20
#define KEY_K 21
#define KEY_L 22
#define KEY_M 23
#define KEY_N 24
#define KEY_O 25
#define KEY_P 26
#define KEY_Q 27
#define KEY_R 28
#define KEY_S 29
#define KEY_T 30
#define KEY_U 31
#define KEY_V 32
#define KEY_W 33
#define KEY_X 34
#define KEY_Y 35
#define KEY_Z 36
#define KEY_L_ALT 37
#define KEY_R_ALT 38
#define KEY_L_ARROW 39
#define KEY_R_ARROW 40
#define KEY_L_CTRL 41
#define KEY_R_CTRL 42
#define KEY_L_GUI 43
#define KEY_R_GUI 44
#define KEY_L_SHFT 45
#define KEY_R_SHFT 46
#define KEY_U_ARROW 47
#define KEY_D_ARROW 48
#define KEY_KP_STAR 49
#define KEY_KP_PLUS 50
#define KEY_KP_DASH 51
#define KEY_KP_PERIOD 52
#define KEY_KP_SLASH 53
#define KEY_KP_0 54
#define KEY_KP_1 55
#define KEY_KP_2 56
#define KEY_KP_3 57
#define KEY_KP_4 58
#define KEY_KP_5 59
#define KEY_KP_6 60
#define KEY_KP_7 61
#define KEY_KP_8 62
#define KEY_KP_9 63
#define KEY_KP_EN 64
#define KEY_F1 65
#define KEY_F2 66
#define KEY_F3 67
#define KEY_F4 68
#define KEY_F5 69
#define KEY_F6 70
#define KEY_F7 71
#define KEY_F8 72
#define KEY_F9 73
#define KEY_F10 74
#define KEY_F11 75
#define KEY_F12 76
#define KEY_QUOTE 77
#define KEY_COMMA 78
#define KEY_DASH 79
#define KEY_PERIOD 80
#define KEY_SLASH 81
#define KEY_SEMICOLON 82
#define KEY_EQUALS 83
#define KEY_APPS 84
#define KEY_BKSP 85
#define KEY_CAPS 86
#define KEY_DELETE 87
#define KEY_END 88
#define KEY_ENTER 89
#define KEY_ESC 90
#define KEY_HOME 91
#define KEY_INSERT 92
#define KEY_NUM 93
#define KEY_PG_DN 94
#define KEY_PG_UP 95
#define KEY_SCROLL 96
#define KEY_SPACE 97
#define KEY_TAB 98
#define KEY_LBRACKET 99
#define KEY_BSLASH 100
#define KEY_RBRACKET 101
#define KEY_BACKTICK 102

#define KEY_MAX_KEY 102

typedef struct vkeyboard vkeyboard_t;

// Create a virtual keyboard.
vkeyboard_t* vkeyboard_create();

// Send a raw keycode (and whether the event is key-up or key-down) to a virtual
// keyboard.
void vkeyboard_send_keycode(vkeyboard_t* kbd, uint8_t code, uint8_t up);

// Attach the output of a virtual keyboard to the given handler.  When the
// keyboard generates ASCII output, it will invoke the handler.  Each keyboard
// can only have one handler at a time.
//
// NOTE: the handler will likely be invoked on an interrupt context, so it
// shouldn't block.
//
// NOTE: this should be called before any keycodes are sent.
void vkeyboard_set_handler(vkeyboard_t* kbd, char_sink_t handler, void* arg);

#endif
