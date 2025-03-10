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

// Utilities to allow linking functions with multiple names, e.g. at both
// physical and virtual memory addresses.
#ifndef APOO_COMMON_MULTILINK_H
#define APOO_COMMON_MULTILINK_H

#ifndef _MULTILINK_SUFFIX
#define _MULTILINK_SUFFIX
#endif

// Wrap around a function name at declaration and definition sites.
#define _MULTILINK_CONCAT2(a, b) a##b
#define _MULTILINK_CONCAT(a, b) _MULTILINK_CONCAT2(a, b)
#define MULTILINK(name) _MULTILINK_CONCAT(name, _MULTILINK_SUFFIX)

#endif
