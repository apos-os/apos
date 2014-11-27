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

#ifndef APOO_DEV_TTY_H
#define APOO_DEV_TTY_H

#include "dev/ld.h"
#include "user/include/apos/dev.h"

// Create a TTY character device over the given ld.  Returns the apos_dev_t of
// the new device.
apos_dev_t tty_create(ld_t* ld);

#endif
