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

#include "dev/termios.h"

#include "dev/ld.h"
#include "dev/tty.h"
#include "dev/tty_util.h"

int tty_tcdrain(int fd) {
  tty_t* tty = NULL;
  int result = tty_get_fd(fd, false, &tty);
  if (result) return result;

  return ld_drain(tty->ld);
}

int tty_tcflush(int fd, int action) {
  tty_t* tty = NULL;
  int result = tty_get_fd(fd, false, &tty);
  if (result) return result;

  return ld_flush(tty->ld, action);
}

int tty_tcgetattr(int fd, struct termios* t) {
  tty_t* tty = NULL;
  int result = tty_get_fd(fd, false, &tty);
  if (result) return result;

  ld_get_termios(tty->ld, t);
  return 0;
}

int tty_tcsetattr(int fd, int optional_actions, const struct termios* t) {
  tty_t* tty = NULL;
  int result = tty_get_fd(fd, false, &tty);
  if (result) return result;

  return ld_set_termios(tty->ld, optional_actions, t);
}
