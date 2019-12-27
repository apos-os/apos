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

CONFIG_CACHE_FILE = 'build-config.conf'

# If the user didn't request 'configure', read the cached config values.
if 'configure' in COMMAND_LINE_TARGETS:
  vars = Variables()
else:
  vars = Variables(CONFIG_CACHE_FILE)

vars.Add(EnumVariable('ARCH', 'architecture to target', None, ['i586', 'x86_64']))
vars.Add(BoolVariable('DEBUG', 'enable debug build', True))
vars.Add('BUILD_DIR', 'directory to build in', 'build-scons')
vars.Add('TOOL_PREFIX', 'prefix of build tools', None)
vars.Add('HEADER_INSTALL_PREFIX', 'where to install userspace headers', '')
vars.Add(BoolVariable('CLANG', 'whether to compile with clang', False))
vars.Add('KSHELL_INITIAL_COMMAND',
  'command to automatically run when kshell starts', '')

# List of modules that can be enabled/disabled.  All are enabled by default.
FEATURES = [
  'ETHERNET',
  'EXT2',
  'TESTS',
  'TERM_COLOR',
  'USB',
  'USER_DUMMY_LIB',
  'USER_TESTS',
  'KMALLOC_HEAP_PROFILE',
]

for feature in FEATURES:
  vars.Add(BoolVariable(feature, 'enable %s' % feature, True))

base_env = Environment(
    variables = vars,
    tools = ['ar', 'as', 'cc', 'textfile', 'default'],
    ENV = {'PATH' : os.environ['PATH']})

base_env.Alias('configure', [])

base_env.SetDefault(BUILD_CFG_DIR =
  os.path.join(base_env['BUILD_DIR'], '%s-%s' %
    (base_env['ARCH'], 'clang' if base_env['CLANG'] else 'gcc')))
base_env.SetDefault(TOOL_PREFIX = '$ARCH-pc-apos-')
base_env.SetDefault(CLANG_TARGET = '$ARCH-pc-apos')

# If the user did a 'configure', save their configuration for later.
if 'configure' in COMMAND_LINE_TARGETS:
  vars.Save(CONFIG_CACHE_FILE, base_env)

if not base_env['CLANG']:
  base_env.Replace(CC = '${TOOL_PREFIX}gcc')
else:
  base_env.Replace(CC = 'clang')
  base_env.Append(CFLAGS = ['-target', '$CLANG_TARGET'])

base_env.Replace(AR = '${TOOL_PREFIX}ar')
base_env.Replace(AS = '${TOOL_PREFIX}as')
base_env.Replace(LD = '${TOOL_PREFIX}ld')
base_env.Replace(RANLIB = '${TOOL_PREFIX}ranlib')
base_env.Replace(STRIP = '${TOOL_PREFIX}strip')

base_env.Append(CFLAGS =
        Split("-Wall -Wextra -Werror -Wundef -std=gnu11 " +
              "-Wno-unused-parameter -Wno-error=unused-function " +
              "-mno-mmx -mno-sse " +
              "-Wstrict-prototypes"))
base_env.Append(CPPDEFINES = ['__APOS_BUILDING_IN_TREE__=1'])
base_env.Append(CPPPATH = ['#'])

base_env.SetDefault(CPPDEFINES = [])

if base_env['DEBUG']:
  base_env.Append(CFLAGS = ['-g3', '-gdwarf-2'])
  base_env.Append(ASFLAGS = ['--gen-debug'])

env = base_env.Clone()

if env['ARCH'] == 'x86_64':
  env.Append(CFLAGS = Split("-mcmodel=large -m64 -mno-red-zone"))

env.Append(CFLAGS = Split("-nostdlib -ffreestanding"))
if not env['CLANG']:
  env.Append(CFLAGS = Split("-nostartfiles -nodefaultlibs"))
  # TODO(aoates): get format-string checking to work with both GCC and clang.
  env.Append(CFLAGS = Split("-Wno-format"))
  # TODO(aoates): get frame sizes under clang small enough to enable this.
  env.Append(CFLAGS = Split("-Wframe-larger-than=1500"))
env.Append(ASFLAGS = ['--gen-debug'])
env.Replace(LINK = '${TOOL_PREFIX}ld')

env.Append(CPPPATH = ['#/archs/$ARCH', '#/archs/common', '#/$BUILD_CFG_DIR'])

# Environment for userspace targets.
user_env = base_env.Clone()
user_env.Append(CPPDEFINES='ENABLE_TERM_COLOR=%d' % user_env['TERM_COLOR'])
if base_env['CLANG']:
  user_env.Append(LINKFLAGS = ['-target', '$CLANG_TARGET'])
  user_env.Append(CFLAGS =
      ['-isystem', '$HEADER_INSTALL_PREFIX/include'])

def AposAddSources(env, srcs, subdirs, **kwargs):
  """Helper for subdirectories."""
  objects = [env.Object(src, **kwargs) for src in srcs]
  for subdir in subdirs:
    objects.append(SConscript('%s/SConscript' % subdir))
  return objects

def kernel_program(env, target, source):
  """Builder for the main kernel file."""
  return [
      env.Depends(target, 'archs/$ARCH/build/linker.ld'),
      env.Program(target, source,
        LINKFLAGS=env['LINKFLAGS'] + [
          '-T', 'archs/$ARCH/build/linker.ld', '-L', Dir('.')])]

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

tpl_bld = Builder(
    action = 'APOS_ARCH=$ARCH util/tpl_gen.py $SOURCE > $TARGET',
    suffix = '.tpl.c',
    src_suffix = '.tpl',
    source_scanner=tpl_scanner)

env.Append(BUILDERS = {'Tpl': tpl_bld})
env.AddMethod(phys_object, 'PhysObject')
env.AddMethod(kernel_program, 'Kernel')

Export('env user_env AposAddSources')

SConscript('SConscript', variant_dir=env['BUILD_CFG_DIR'], duplicate=False)
