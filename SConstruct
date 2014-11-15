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

import os
import re

AddOption('--arch', default='i586', help='architecture to target')

env = Environment(
    tools = ['ar', 'as', 'cc', 'textfile', 'default'],
    ENV = {'PATH' : os.environ['PATH']})

env['ARCH'] = env.GetOption('arch')
TOOL_PREFIX = '%s-pc-apos' % env['ARCH']

env.Replace(AR = '%s-ar' % TOOL_PREFIX)
env.Replace(AS = '%s-as' % TOOL_PREFIX)
env.Replace(CC = '%s-gcc' % TOOL_PREFIX)
env.Replace(LINK = '%s-ld' % TOOL_PREFIX)
env.Replace(RANLIB = '%s-ranlib' % TOOL_PREFIX)
env.Replace(STRIP = '%s-strip' % TOOL_PREFIX)

env.Append(CFLAGS =
        Split("-Wall -Wextra -Werror -nostdlib -ffreestanding -std=gnu11 -g3 " +
              "-Wno-unused-parameter -Wno-error=unused-function " +
              "-Wstrict-prototypes -nostartfiles -nodefaultlibs"))
env.Append(ASFLAGS = ['--gen-debug'])

env.Append(CPPDEFINES = ['ENABLE_KERNEL_SAFETY_NETS=1'])
env.Append(CPPPATH = ['#', '#/archs/%s' % env['ARCH'], '#/archs/common'])

def AposAddSources(env, srcs, subdirs):
  """Helper for subdirectories."""
  objects = [env.Object(src) for src in srcs]
  for subdir in subdirs:
    objects.append(SConscript('%s/SConscript' % subdir))
  return objects

def kernel_program(env, target, source):
  """Builder for the main kernel file."""
  return [
      env.Depends(target, 'archs/%s/build/linker.ld' % env['ARCH']),
      env.Program(target, source,
        LINKFLAGS=env['LINKFLAGS'] + [
          '-T', 'archs/%s/build/linker.ld' % env['ARCH'], '-L', Dir('.')])]

def phys_object(env, source):
  """Builder for object files that need to be linked in the physical (not
  virtual) address space, i.e. the code run at boot before paging is
  configured."""
  return [env.Object(source, OBJSUFFIX='.PHYS.o',
    CPPDEFINES=env['CPPDEFINES'] + ['_MULTILINK_SUFFIX=_PHYS'])]

def tpl_scanner_func(node, env, paths, arg=None):
  """Depedency scanner for .tpl files."""
  text = node.get_text_contents()
  deps = []
  for _, path in re.findall('{%[^}]*(import|include)\s*"([^"]*)"', text):
    deps.append(path)
  for path in re.findall('PY_IMPORT\s*(\S*)', text):
    deps.append(path)
  return env.File(deps)

def filter_tpl(nodes):
  """Return the nodes in the list that are .tpl files, for recursive dependency
  scanning."""
  return [n for n in nodes if n.path.endswith('.tpl')]

tpl_scanner = Scanner(function=tpl_scanner_func, skeys=['.tpl'],
    recursive=filter_tpl)

tpl_bld = Builder(action = 'util/tpl_gen.py $SOURCE > $TARGET',
    suffix = '.tpl.c',
    src_suffix = '.tpl',
    source_scanner=tpl_scanner)

env.Append(BUILDERS = {'Tpl': tpl_bld})
env.AddMethod(phys_object, 'PhysObject')
env.AddMethod(kernel_program, 'Kernel')

Export('env AposAddSources')

SConscript('SConscript', variant_dir='build-scons', duplicate=False)
