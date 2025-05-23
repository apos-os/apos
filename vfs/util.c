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

#include "vfs/util.h"

#include "common/kstring.h"

static void reverse_string(char* begin, char* end) {
  while (begin < end) {
    const char tmp = *begin;
    *begin = *end;
    *end = tmp;
    begin++;
    end--;
  }
}

void reverse_path(char* path) {
  const int len = kstrlen(path);
  reverse_string(path, path + len - 1);

  while (*path) {
    while (*path && *path == '/') path++;

    char* end = path;
    while (*end && *end != '/') end++;

    reverse_string(path, end - 1);
    path = end;
  }
}
