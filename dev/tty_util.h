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
#ifndef APOO_DEV_TTY_UTIL_H
#define APOO_DEV_TTY_UTIL_H

#include "dev/tty.h"

// Get the TTY associated with the given file descriptor, or return NULL.
//
// If require_ctty is true, then the fd must refer to the controlling terminal
// of the calling process; if it isn't, -ENOTTY is returned.
int tty_get_fd(int fd, bool require_ctty, tty_t** tty);

// Returns 0 if the current process can read the given TTY, or raises a signal
// and returns -error.
int tty_check_read(const tty_t* tty);

// Returns 0 if the current process can write or modify the given TTY (i.e.
// either the TTY is not the controlling terminal of the process, or it is and
// the process is in the fg pgroup and SIGTTOU is not blocked).  Otherwise,
// returns -error and possibly raises SIGTTOU.
int tty_check_write(const tty_t* tty);

#endif
