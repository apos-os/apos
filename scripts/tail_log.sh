#!/bin/bash
# Copyright 2014 Andrew Oates.  All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

tail -c +0 -f log.txt | \
  sed -u "s/\[PASSED\]/\x1b[32;1m\0\x1b[0m/g" | \
  sed -u "s/\[FAILED\]/\x1b[31;1m\0\x1b[0m/g" | \
  sed -u "s/^@.*@$/\x1b[36;1m\0\x1b[0m/g" | \
  ./scripts/symbolize.py
