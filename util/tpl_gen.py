#!/usr/bin/env python
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

# Generates code from a .tpl file, which is a jinja2 template.  The template
# will be instantiated and printed.
#
# If the template includes lines of the form '{# PY_IMPORT <file> #}', the given
# python file will be read and interpreted in the template's environment before
# the template is instantiated.
#
# Usage:
#   tpl_gen.py <template file>

import jinja2
import os
import re
import sys

def main(argv):
  if len(argv) != 2:
    print >> sys.stderr, 'Usage: %s.py <template>' % os.path.basename(argv[0])
    sys.exit(1)

  tpl_file = argv[1]

  # Find modules to import.
  python_env = {}
  with open(tpl_file) as f:
    for line in f.readlines():
      m = re.search('\{#\s*PY_IMPORT\s*(\S*)', line)
      if m:
        comp = compile(open(m.group(1)).read(), m.group(1), 'exec')
        eval(comp, python_env)

  env = jinja2.Environment(
      loader=jinja2.FileSystemLoader(['.', os.path.dirname(tpl_file)]),
      trim_blocks=True,
      undefined=jinja2.StrictUndefined,
      extensions=['jinja2.ext.do'])
  template = env.get_template(tpl_file)
  print(template.render(python_env))

if __name__ == '__main__':
  main(sys.argv)

