{#
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
 #-}

{# Manually implemented syscall stubs. -#}
// mknod needs a special stub to decompose the apos_dev_t struct.
// TODO(aoates): use POSIX dev_t here.
int mknod(const char* path, uint32_t mode, apos_dev_t dev) {
  return _do_mknod(path, mode, major(dev), minor(dev));
}

void _exit(int status) {
  _do_exit(status);
}
