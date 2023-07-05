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

vars.Add(EnumVariable('ARCH', 'architecture to target', None,
                      ['i586', 'x86_64', 'riscv64']))
vars.Add(BoolVariable('DEBUG', 'enable debug build', True))
vars.Add('BUILD_DIR', 'directory to build in', 'build-scons')
vars.Add('TOOL_PREFIX', 'prefix of build tools', None)
vars.Add('HEADER_INSTALL_PREFIX', 'where to install userspace headers', '')
vars.Add(BoolVariable('CLANG', 'whether to compile with clang', False))
vars.Add('KSHELL_INITIAL_COMMAND',
  'command to automatically run when kshell starts', '')

# List of modules that can be enabled/disabled.  All are enabled by default,
# unless unsupported by the current architecture.
FEATURES_DEFAULT_ENABLED = [
  'ETHERNET',
  'EXT2',
  'TESTS',
  'TERM_COLOR',
  'USB',
  'USER_DUMMY_LIB',
  'USER_OS',
  'USER_TESTS',
  'KMALLOC_HEAP_PROFILE',
]

# As above, but features that are _disabled_ by default.
FEATURES_DEFAULT_DISABLED = [
  'KMUTEX_DEADLOCK_DETECTION',
]

ALL_FEATURES = FEATURES_DEFAULT_ENABLED + FEATURES_DEFAULT_DISABLED

vars.Add(ListVariable('enable', 'features to force-enable', [], ALL_FEATURES))
vars.Add(ListVariable('disable', 'features to force-disable', [], ALL_FEATURES))

# base_env captures common parameters and configuration across _all_ target
# types --- kernel code, user code, and native (build system) code.
base_env = Environment(
    variables = vars,
    tools = ['ar', 'as', 'cc', 'textfile', 'default'],
    ENV = {'PATH' : os.environ['PATH'], 'TERM': os.environ['TERM']})

base_env.Alias('configure', [])

# Validate that the same features are not simultaneously enabled and disabled.
def _ValidateFeatures(env):
  feature_overlap = set(env['enable']).intersection(env['disable'])
  if feature_overlap:
    print('Features cannot be force-enabled and force-disabled: %s' %
        ' '.join(feature_overlap))
    Exit(1)
_ValidateFeatures(base_env)

# Insert non-disabled features into the environment (this can be overridden by
# other SConscript files, in particular architecture-specific ones).
for feature in FEATURES_DEFAULT_ENABLED:
  base_env.SetDefault(**{feature: feature not in base_env['disable']})

for feature in FEATURES_DEFAULT_DISABLED:
  base_env.SetDefault(**{feature: feature in base_env['enable']})

base_env.SetDefault(BUILD_VARIANT_NAME = '%s-%s' %
    (base_env['ARCH'], 'clang' if base_env['CLANG'] else 'gcc'))
base_env.SetDefault(BUILD_CFG_DIR =
  os.path.join(base_env['BUILD_DIR'], base_env['BUILD_VARIANT_NAME']))
base_env.SetDefault(TOOL_PREFIX = '$ARCH-pc-apos-')
base_env.SetDefault(CLANG_TARGET = '$ARCH-pc-apos')

# If the user did a 'configure', save their configuration for later.
if 'configure' in COMMAND_LINE_TARGETS:
  vars.Save(CONFIG_CACHE_FILE, base_env)

# TODO(aoates): figure out the right way to express these as part of the build
# system (e.g. as a root dependency for everything else?)
def do_link(symlink_path):
  if os.path.exists(symlink_path):
    os.remove(symlink_path)
  os.symlink(base_env['BUILD_VARIANT_NAME'], symlink_path)
do_link(os.path.join(base_env['BUILD_DIR'], 'latest'))
do_link(os.path.join(base_env['BUILD_DIR'], 'latest-%s' % base_env['ARCH']))

base_env.Append(CFLAGS =
        Split("-Wall -Wextra -Werror -Wundef -std=gnu11 " +
              "-Wno-unused-parameter -Wno-error=unused-function " +
              "-Wstrict-prototypes"))
base_env.Append(CPPDEFINES = ['__APOS_BUILDING_IN_TREE__=1'])
base_env.Append(CPPPATH = ['#'])

base_env.SetDefault(CPPDEFINES = [])

if base_env['DEBUG']:
  base_env.Append(CFLAGS = ['-g3', '-gdwarf-2'])
  base_env.Append(ASFLAGS = ['--gen-debug'])

# Ensure all envs have CompilationDatabase loaded.  Only one will trigger it,
# though, from SConscript.
base_env.Tool('compilation_db')

# target_env is for targets built for the APOS target (kernel and user code).
target_env = base_env.Clone()

if not target_env['CLANG']:
  target_env.Replace(CC = '${TOOL_PREFIX}gcc')
else:
  target_env.Replace(CC = 'clang')
  target_env.Append(CFLAGS = ['-target', '$CLANG_TARGET'])
  target_env.Append(CFLAGS = ['-fdebug-macro'])

target_env.Replace(AR = '${TOOL_PREFIX}ar')
target_env.Replace(AS = '${TOOL_PREFIX}as')
target_env.Replace(LD = '${TOOL_PREFIX}ld')
target_env.Replace(RANLIB = '${TOOL_PREFIX}ranlib')
target_env.Replace(STRIP = '${TOOL_PREFIX}strip')
target_env.Append(LINKFLAGS = ['-z', 'noexecstack'])

env = target_env.Clone()
env.Append(CPPDEFINES = ['__APOS_BUILDING_KERNEL__=1'])

env.Append(CFLAGS = Split("-nostdlib -ffreestanding"))
if not env['CLANG']:
  env.Append(CFLAGS = Split("-nostartfiles -nodefaultlibs"))
  # TODO(aoates): get format-string checking to work with both GCC and clang.
  env.Append(CFLAGS = Split("-Wno-format"))
env.Append(CFLAGS = Split("-Wframe-larger-than=1500"))
env.Append(ASFLAGS = ['--gen-debug'])
env.Replace(LINK = '${TOOL_PREFIX}ld')

env.Append(CPPPATH = ['#/archs/$ARCH', '#/archs/common', '#/$BUILD_CFG_DIR'])

# Environment for userspace targets.
user_env = target_env.Clone()
user_env.Append(CPPDEFINES='ENABLE_TERM_COLOR=%d' % user_env['TERM_COLOR'])
if user_env['CLANG']:
  user_env.Append(LINKFLAGS = ['-target', '$CLANG_TARGET'])
  user_env.Append(CFLAGS =
      ['-isystem', '$HEADER_INSTALL_PREFIX/include'])

# Environment for build-system native targets.
native_env = base_env.Clone()
native_env['OBJPREFIX'] = 'native-'
native_env['LIBPREFIX'] = 'native-'
native_env.Append(CPPDEFINES='APOS_NATIVE_TARGET=1')

def AposAddSources(env, srcs, subdirs, **kwargs):
  """Helper for subdirectories."""
  # Turn each source file path into an Object, if not already one.
  make_obj = lambda src: env.Object(src, **kwargs) if type(src) == str else src
  objects = [make_obj(src) for src in srcs]
  for subdir in subdirs:
    objects.append(SConscript('%s/SConscript' % subdir))
  return objects

def DisableFeature(env, feature):
  """Causes the given feature to be disabled by default.

  This can be overridden by explicitly enabling the feature with the
  `enable=FOO` build option.
  """
  assert(feature in ALL_FEATURES)
  env.Replace(**{feature: feature in env['enable']})

def kernel_program(env, target, source):
  """Builder for the main kernel file."""
  return [
      env.Depends(target, 'archs/$ARCH/build/linker.ld'),
      env.Program(target, source,
        LINKFLAGS=env['LINKFLAGS'] +
                  ['-T', 'archs/$ARCH/build/linker.ld'])]

def phys_object(env, source):
  """Builder for object files that need to be linked in the physical (not
  virtual) address space, i.e. the code run at boot before paging is
  configured."""
  return [env.Object(source, OBJSUFFIX='.PHYS.o',
    CPPDEFINES=['$CPPDEFINES', '_MULTILINK_SUFFIX=_PHYS'])]

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
    action = 'APOS_ARCH=$ARCH util/tpl_gen.py $SOURCE | clang-format > $TARGET',
    suffix = '.tpl.c',
    src_suffix = '.tpl',
    source_scanner=tpl_scanner)

# Variant/wrapper of the Tpl builder that causes the source file to be generated
# in the source tree (e.g. so it can be checked in).
# N.B.(aoates): this causes SCons to not mirror the (generated) source file over
# to the build directory if duplicating is enabled.  I don't think it matters.
def tpl_source_build(env, target, source):
  # Creates the source code File object to be generated (in the source tree).
  tpl = env.Tpl(target, source)
  # Creates the object file, setting the target explicitly to the source file
  # with the appropriate suffix so that it's generated in the build directory,
  # _not_ the source directory (unlike the source file).
  obj = env.Object(target=source + '$OBJSUFFIX', source=tpl)
  return [obj]

env.Append(BUILDERS = {'Tpl': tpl_bld})
env.AddMethod(phys_object, 'PhysObject')
env.AddMethod(kernel_program, 'Kernel')
env.AddMethod(tpl_source_build, 'TplSource')

Export('env user_env native_env AposAddSources DisableFeature')

SConscript('SConscript', variant_dir=env['BUILD_CFG_DIR'], duplicate=False)
