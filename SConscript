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

Import('env AposAddSources')

env.CompilationDatabase()

# Execute architecture-specific pre-build hooks, if any.
arch_pre_sconscript = FindFile('SConscript.pre', env.subst('archs/$ARCH'))
if arch_pre_sconscript:
  SConscript(arch_pre_sconscript)

srcs = []

SUBDIRS = [
  'archs',
  'common',
  'dev',
  'main',
  'memory',
  'net',
  'proc',
  'sanitizers',
  'syscall',
  'util',
  'vfs',
]

NON_KERNEL_SUBDIRS = [
  'user',
]

if env['TESTS']:
  SUBDIRS.append('test')

if env['USER_TESTS']:
  NON_KERNEL_SUBDIRS.append('user-tests')

if env['USER_OS']:
  NON_KERNEL_SUBDIRS.append('os')

all_objects = Flatten(AposAddSources(env, srcs, SUBDIRS))

objects = [obj for obj in all_objects if obj.name.count('PHYS') == 0]
phys_objects = [obj for obj in all_objects if obj.name.count('PHYS') > 0]

physlib = env.StaticLibrary('libkernel_phys', phys_objects)
kernel_lib = env.StaticLibrary('kernel', Flatten(objects))
kernel = env.Kernel('kernel.bin', [physlib, kernel_lib])
env.Command('kernel.bin.stripped', 'kernel.bin', '%s -s $SOURCE -o $TARGET' % env['STRIP'])

env.Install(os.path.join('#', env['BUILD_DIR']), 'kernel.bin')
env.Install(os.path.join('#', env['BUILD_DIR']), 'kernel.bin.stripped')

for subdir in NON_KERNEL_SUBDIRS:
  SConscript(os.path.join(subdir, 'SConscript'))
