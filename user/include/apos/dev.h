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
#ifndef APOO_USER_DEV_H
#define APOO_USER_DEV_H

#include <stdint.h>

// A device identifier.
typedef uint32_t apos_dev_t;

#define APOS_DEV_INVALID ((apos_dev_t)-1)

static inline apos_dev_t kmakedev(unsigned int major, unsigned int minor) {
  return (major << 16) | (minor & 0xFFFF);
}

static inline unsigned int kmajor(apos_dev_t dev) { return dev >> 16; }
static inline unsigned int kminor(apos_dev_t dev) { return dev & 0xFFFF; }

#if !__APOS_BUILDING_KERNEL__
  typedef apos_dev_t dev_t;
# define makedev(major, minor) kmakedev(major, minor)
# define major(dev) kmajor(dev)
# define minor(dev) kminor(dev)
#endif

#endif
