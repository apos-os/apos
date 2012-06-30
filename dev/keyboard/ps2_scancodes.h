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

// Tables and constants for translating scancodes from the PS/2 keyboard into
// keys.
#ifndef APOO_DEV_KEYBOARD_PS2_SCANCODES_H
#define APOO_DEV_KEYBOARD_PS2_SCANCODES_H

// Given a scancode and is-extended bit, returns the corresponding key code from
// keyboard.h.  Returns NONE if the scancode is invalid.
uint32_t ps2_convert_scancode(uint8_t scancode, uint8_t is_extended);

#endif
