#!/bin/bash -x
# Copyright 2026 Andrew Oates.  All Rights Reserved.
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


#perl -pe 's/-MMD -MF \S* *//g' | \
#  perl -pe 's/\.\.\/\.\././g' | \
#  perl -pe 's/\.\///g' | \
#  perl -pe 's/kernel\.(.*)\.o/\1.o/g' | \
#  perl -pe 's/obj\//build-scons\/i586-gcc\//g' | \
#  perl -pe 's/(apos-\S*) (.*) (-o \S*)/\1 \3 \2/g' | \

DIR=$(dirname $0)
grep '\[\d*/\d*\]' | \
  perl -p -e 's/^\[\d*\/\d*\] *//g' | \
  perl -p -e 's/rm -f.*&&//g' | \
  ${DIR}/normalize_args.py "$@" | \
  sort
