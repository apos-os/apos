// Copyright 2015 Andrew Oates.  All Rights Reserved.
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
#ifndef APOO_USER_INCLUDE_APOS_VFS_POLL_H
#define APOO_USER_INCLUDE_APOS_VFS_POLL_H

#if __APOS_BUILDING_KERNEL__
#  define _APOS_POLLFD apos_pollfd
#else
#  define _APOS_POLLFD pollfd
#endif
struct _APOS_POLLFD {
  int fd;
  short events;
  short revents;
};
#undef _APOS_POLLFD

typedef unsigned long apos_nfds_t;

#define POLLIN      0x001  // Data other than high-priority data may be read without blocking.
#define POLLRDNORM  0x002  // Normal data may be read without blocking.
#define POLLRDBAND  0x004  // Priority data may be read without blocking.
#define POLLPRI     0x008  // High priority data may be read without blocking.
#define POLLOUT     0x010  // Normal data may be written without blocking.
#define POLLWRNORM  0x010  // Equivalent to POLLOUT.
#define POLLWRBAND  0x020  // Priority data may be written.
#define POLLERR     0x040  // An error has occurred (revents only).
#define POLLHUP     0x080  // Device has been disconnected (revents only).
#define POLLNVAL    0x100  // Invalid fd member (revents only).

#if !__APOS_BUILDING_KERNEL__
  typedef apos_nfds_t nfds_t;
# define apos_pollfd pollfd
#endif

#endif
