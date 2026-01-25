#!/usr/bin/env python3
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

import argparse
import jinja2
import jinja2.meta
import os
import re
import subprocess
import sys


# TODO(aoates): dedup this with the one in config_gen.py?
def write_if_changed(file_path, new_content):
  try:
    with open(file_path, 'r') as f:
      if f.read() == new_content:
        return  # Do nothing, preserving the old timestamp
  except (FileNotFoundError, IOError):
    # File doesn't exist or isn't readable; proceed to write
    pass

  with open(file_path, 'w') as f:
    f.write(new_content)


def clang_format(buf):
  p = subprocess.run(["clang-format"],
                     input=buf,
                     capture_output=True,
                     text=True,
                     check=True,
                     encoding='utf-8')
  return p.stdout


def main(argv):
  parser = argparse.ArgumentParser()
  parser.add_argument("template")
  parser.add_argument("--outfile",
                      help="Output filename.  If not given, stdout is used")
  parser.add_argument("--depsfile", help="Filename to write dependencies in gcc format")
  parser.add_argument("--clang-format",
                      help="Whether to run clang-format on the output",
                      action="store_true")
  args = parser.parse_args()
  tpl_file = args.template

  # Find modules to import.
  python_env = {}
  deps = []
  with open(tpl_file) as f:
    for line in f.readlines():
      m = re.search(r'\{#\s*PY_IMPORT\s*(\S*)', line)
      if m:
        path = m.group(1)
        comp = compile(open(path).read(), path, 'exec')
        eval(comp, python_env)
        deps.append(path)

  env = jinja2.Environment(
      loader=jinja2.FileSystemLoader(['.', os.path.dirname(tpl_file)]),
      trim_blocks=True,
      undefined=jinja2.StrictUndefined,
      extensions=['jinja2.ext.do'])
  template = env.get_template(tpl_file)
  ast = env.parse(open(tpl_file).read())
  # TODO(aoates): make this work recursively (it currently does not)
  template_deps = jinja2.meta.find_referenced_templates(ast)
  deps.extend(template_deps)
  output = template.render(python_env)

  if args.clang_format:
    output = clang_format(output)

  if args.outfile:
    write_if_changed(args.outfile, output)
  else:
    print(output)

  if args.depsfile:
    deps_str = " ".join(deps)
    write_if_changed(args.depsfile, f'{args.outfile}: {deps_str}\n')

if __name__ == '__main__':
  main(sys.argv)
