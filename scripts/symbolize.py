#!/usr/bin/python
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

# Given a log file, look for stack traces and symbolize them.

import errno
import re
import sys
import subprocess

def read_config():
  try:
    conf_str = open('build-config.conf').read()
  except IOError:
    print >> sys.stderr, ('Unable to open build-config.conf; '
        'please run scons configure')
    sys.exit(1)

  conf = {}
  exec(conf_str, {}, conf)
  expanded_conf = {}
  for k, v in conf.items():
    if type(v) == type(''):
      expanded_conf[k] = v.replace('$ARCH', conf['ARCH'])
    else:
      expanded_conf[k] = v
  return expanded_conf

def get_tool_prefix():
  conf = read_config()
  if 'TOOL_PREFIX' not in conf:
    print >> sys.stderr, 'TOOL_PREFIX not in build-config.conf'
    sys.exit(1)
  return conf['TOOL_PREFIX']

def symbolize(tool_prefix, frame_num, addr):
  p = subprocess.Popen(["%saddr2line" % tool_prefix, "-f", "-s", "-e",
                        "build-scons/kernel.bin", addr],
                       stdout=subprocess.PIPE)
  output = p.communicate()[0].split('\n')
  function = output[0]
  file_line = output[1]
  return ' #%s %s in %s() [%s]\n' % (frame_num, addr, function, file_line)

TOOL_PREFIX = get_tool_prefix()

try:
  while True:
    line = sys.stdin.readline()
    if not line: sys.exit(0)
    m = re.match(" #(\d*) (0x[a-zA-Z0-9]*)\n", line)
    if m:
      line = symbolize(TOOL_PREFIX, m.group(1), m.group(2))
    print line,
    sys.stdout.flush()
except KeyboardInterrupt:
  sys.stdout.flush()
  pass
except IOError as e:
  if e.errno == errno.EPIPE:
    sys.exit(0)
  raise e
