// Copyright 2018 Andrew Oates.  All Rights Reserved.
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

#ifndef APOO_NET_INET_H
#define APOO_NET_INET_H

// Minimum and maximum ports.
#define INET_PORT_ANY 0
#define INET_PORT_MIN 1
#define INET_PORT_MAX 65535

// Range of ephemeral ports.  This should be configurable.
#define INET_PORT_EPHMIN 32768
#define INET_PORT_EPHMAX 65535

#endif
