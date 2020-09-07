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
#ifndef APOO_USER_INCLUDE_APOS_TERMIOS_H
#define APOO_USER_INCLUDE_APOS_TERMIOS_H

#if __APOS_BUILDING_IN_TREE__
#  include "user/include/apos/_posix_termios_constants.h"
#else
#  include <apos/_posix_termios_constants.h>
#endif

typedef unsigned char cc_t;
typedef unsigned short speed_t;
typedef unsigned int tcflag_t;

struct termios {
  tcflag_t c_iflag;  // Input mode flags.
  tcflag_t c_oflag;  // Output mode flags.
  tcflag_t c_cflag;  // Control mode flags.
  tcflag_t c_lflag;  // Local mode flags.
  cc_t     c_cc[NCCS];  // Control characters.
};

#endif
