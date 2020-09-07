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

typedef unsigned char kcc_t;
typedef unsigned short kspeed_t;
typedef unsigned int ktcflag_t;

#if __APOS_BUILDING_KERNEL__
#  define _APOS_TERMIOS ktermios
#else
#  define _APOS_TERMIOS termios
#endif
struct _APOS_TERMIOS {
  ktcflag_t c_iflag;  // Input mode flags.
  ktcflag_t c_oflag;  // Output mode flags.
  ktcflag_t c_cflag;  // Control mode flags.
  ktcflag_t c_lflag;  // Local mode flags.
  kcc_t     c_cc[NCCS];  // Control characters.
};
#undef _APOS_TERMIOS

// Rename types and functions to POSIX names for user code.
#if !__APOS_BUILDING_KERNEL__
  typedef kcc_t cc_t;
  typedef kspeed_t speed_t;
  typedef ktcflag_t tcflag_t;
# define ktermios termios
#endif // !__APOS_BUILDING_KERNEL__

#endif
