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

// POSIX terminal control functions.
#ifndef APOO_DEV_TERMIOS_H
#define APOO_DEV_TERMIOS_H

#include "common/types.h"
#include "user/include/apos/termios.h"

int tty_tcdrain(int fd);
int tty_tcflush(int fd, int action);
int tty_tcgetattr(int fd, struct termios* t);
int tty_tcsetattr(int fd, int optional_actions, const struct termios* t);

#endif
