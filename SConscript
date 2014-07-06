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

Import('env AposAddSources')

objs = []

SUBDIRS = [
  'common',
  'dev',
  'load',
  'main',
  'memory',
  'proc',
  'syscall',
  'test',
  'util',
  'vfs',
]

all_objects = Flatten(AposAddSources(env, objs, SUBDIRS))

objects = [obj for obj in all_objects if obj.name.count('PHYS') == 0]
phys_objects = [obj for obj in all_objects if obj.name.count('PHYS') > 0]

physlib = env.StaticLibrary('libkernel_phys', phys_objects)
kernel = env.Kernel('kernel.bin', Flatten(objects))
env.Depends(kernel, physlib)
env.Command('kernel.bin.stripped', 'kernel.bin', 'strip -s $SOURCE -o $TARGET')
