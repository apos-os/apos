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

# Generates a deps file for a jinja2 template file.

TPL_FILE=$1

TMPFILE=$(tempfile)

# TODO(aoates): properly recursively find the entire transitive closure of deps.
grep < $TPL_FILE -o "{#\s*PY_IMPORT\s*\S*" | \
  sed "s/.*PY_IMPORT\s*\(\S*\)/\1/g" \
  >> ${TMPFILE}

grep < $TPL_FILE -o "{%\s*\(import\|include\)\s*\"[^\"*]*\"" | \
  sed "s/.*\(import\|include\)\s*\"\([^\"]*\)\"/\2/g" \
  >> ${TMPFILE}

grep < $TPL_FILE -o "^#include\s*\"[^\"]*\"" | \
  sed "s/.*#include\s*\"\([^\"]*\)\"/\1/g" \
  >> ${TMPFILE}

DEPS=$(tr < $TMPFILE "\n" " ")
rm $TMPFILE

echo "$TPL_FILE: $DEPS"
