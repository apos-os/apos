// Copyright 2021 Andrew Oates.  All Rights Reserved.
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

#ifndef APOO_OS_COMMON_PASSWD_H
#define APOO_OS_COMMON_PASSWD_H

#include <pwd.h>
#include <stdio.h>

int apos_get_pwent_f(FILE* passwd_file, const char* user, struct passwd* pwd,
                     char* buf, size_t bufsize);
int apos_get_pwent(const char* user, struct passwd* pwd, char* buf,
                   size_t bufsize);

// Read the shadow password entry for the given user into the buffer.  Returns
// the number of characters read, or -1 on error.
int apos_get_shpwent_f(FILE* shadow_file, const char* user, char* buf,
                       size_t bufsize);
int apos_get_shpwent(const char* user, char* buf, size_t bufsize);

#endif
