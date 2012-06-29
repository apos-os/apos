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

// PS/2 keyboard driver.
//
// Contains code for,
//  a) receiving interrupts (IRQs) from the keyboard, and reading its data
//  b) transforming raw scancodes from the PS/2 keyboard into portable constants
#ifndef APOO_KEYBOARD_PS2_KEYBOARD_H
#define APOO_KEYBOARD_PS2_KEYBOARD_H

// Initializes the PS/2 keyboard.  Returns 1 if a keyboard was found and
// initalization succeeded.
//
// REQUIRES: ps2_init() was called and successful.
int ps2_keyboard_init();

#endif
