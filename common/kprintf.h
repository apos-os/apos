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

#ifndef APOO_KPRINTF_H
#define APOO_KPRINTF_H

#include <stdarg.h>

#include "common/types.h"

int ksprintf(char* str, const char* fmt, ...)
    __attribute__((format(printf, 2, 3)));
int ksnprintf(char* str, size_t size, const char* fmt, ...)
    __attribute__((format(printf, 3, 4)));
int kvsnprintf(char* str, size_t size, const char* fmt, va_list args);

#endif
