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
#include "common/kassert.h"
#include "common/klog.h"
#include "syscall/wrappers32.h"
#include "user/include/apos/time_types.h"

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

int getsockopt_tvms(void* val, socklen_t* val_len, long option_value) {
  if (option_value < -1 || option_value == 0) {
    klogfm(KL_NET, DFATAL, "Invalid sockopt timeval value: %ld\n",
           option_value);
    return -EINVAL;
  }

  if (option_value < 0) {
    option_value = 0;
  }

  struct apos_timeval tv;
  tv.tv_sec = option_value / 1000;
  tv.tv_usec = (option_value % 1000) * 1000;
  size_t buflen = *val_len;
  int result = timeval_to_user(&tv, val, &buflen);
  if (result) {
    return result;
  }
  *val_len = buflen;
  return 0;
}

int setsockopt_tvms(const void* val, socklen_t val_len, long* option_value) {
  struct apos_timeval tv;
  int result = timeval_from_user(val, val_len, &tv);
  if (result) {
    return result;
  }
  if (tv.tv_sec > LONG_MAX / 1000 || tv.tv_sec < 0) {
    return -ERANGE;
  }
  if (tv.tv_usec > 1000000 || tv.tv_usec < 0) {
    return -ERANGE;
  }
  if (tv.tv_sec == 0 && tv.tv_usec == 0) {
    *option_value = -1;
  } else {
    *option_value = tv.tv_sec * 1000 + tv.tv_usec / 1000;
    KASSERT_DBG(*option_value >= 0);
    if (*option_value == 0) *option_value = 1;
  }
  return 0;
}
