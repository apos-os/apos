// Copyright 2023 Andrew Oates.  All Rights Reserved.
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
#include "net/socket/sockopt.h"

#include "common/errno.h"

int getsockopt_int(void* val, socklen_t* val_len, int option_value) {
  if (*val_len < (int)sizeof(int)) {
    return -ENOMEM;
  }
  *val_len = sizeof(int);
  *(int*)val = option_value;
  return 0;
}

int setsockopt_int(const void* val, socklen_t val_len, int* option_value) {
  if (val_len != (int)sizeof(int)) {
    return -EINVAL;
  }
  *option_value = *(const int*)val;
  return 0;
}
