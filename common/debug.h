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

#ifndef APOO_DEBUG_H
#define APOO_DEBUG_H

#ifndef ENABLE_KERNEL_SAFETY_NETS

// If set, various safety nets will be enabled.  This includes things like
// clobbering all memorying when it's allocated or freed, checking for
// double-frees and memory corruption, etc.
#define ENABLE_KERNEL_SAFETY_NETS 0

#endif

#endif
