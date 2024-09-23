// Copyright 2024 Andrew Oates.  All Rights Reserved.
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

#ifndef APOO_NET_TEST_UTIL_H
#define APOO_NET_TEST_UTIL_H

#include "common/types.h"
#include "net/pbuf.h"

// Write the given pbuf to an FD, free it, and set the pointer to NULL.
ssize_t pbuf_write(int fd, pbuf_t** pb);

#endif
