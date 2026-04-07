#!/usr/bin/python3
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
# Usage:
#   symbolize.py [--batch]
#
# If run with --batch, it will symbolize each line in the file in batch mode
# (collecting multiple addresses to symbolize at once).  Otherwise, it will
# symbolize line by line.
#
# Batch mode is much faster but should only be used when reading from a file ---
# otherwise the output risks getting "stuck" for an arbitrarily long period of
# time while a batch chunk is internally buffered.

import errno
import re
import sys
import subprocess
import select

# Configuration constants
BATCH_SIZE = 1000  # Maximum number of lines to batch before processing

def read_config():
  try:
    conf_str = open('build-config.conf').read()
  except IOError:
    print('Unable to open build-config.conf; please run scons configure',
          file=sys.stderr)
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
    print('TOOL_PREFIX not in build-config.conf', file=sys.stderr)
    sys.exit(1)
  return conf['TOOL_PREFIX']

# Explicit cache for symbolized addresses
address_cache = {}

def batch_symbolize(tool_prefix, addresses):
  """Symbolize multiple addresses in a single addr2line call."""
  if not addresses:
    return {}

  # Filter out addresses already in cache.
  uncached_addresses = [addr for addr in addresses if addr not in address_cache]

  if uncached_addresses:
    # Call addr2line with all uncached addresses at once
    cmd = ["%saddr2line" % tool_prefix, "-f", "-s", "-e", "out/latest/kernel.bin"] + uncached_addresses
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True)
    output = p.communicate()[0].strip()

    if output:
      lines = output.split('\n')
      # addr2line outputs 2 lines per address: function name, then file:line
      for i, addr in enumerate(uncached_addresses):
        if i * 2 + 1 < len(lines):
          function = lines[i * 2]
          file_line = lines[i * 2 + 1]
          address_cache[addr] = (function, file_line)
        else:
          # Fallback if output is malformed
          address_cache[addr] = ("??", "??:0")

  # Return results for all requested addresses (from cache)
  return {addr: address_cache.get(addr, ("??", "??:0")) for addr in addresses}

def format_symbolized_line(prefix, frame_num, addr, function, file_line):
  """Format a symbolized line"""
  return '%s #%s %s in %s() [%s]\n' % (prefix, frame_num, addr, function, file_line)

def process_line_buffer(tool_prefix, line_buffer):
  """Process all lines in the buffer using two-pass approach for symbolizable lines"""
  if not line_buffer:
    return

  # Pass 1: Collect all addresses from symbolizable lines and prepare line data.
  all_addresses = set()
  line_data = []

  for line in line_buffer:
    if is_symbolizable_line(line):
      parsed = parse_symbolizable_line(line)
      assert parsed is not None
      _, _, addr = parsed
      all_addresses.add(addr)
      line_data.append((line, parsed))
    else:
      line_data.append((line, None))

  # Symbolize all addresses at once
  resolved = batch_symbolize(tool_prefix, all_addresses)

  # Pass 2: Output all lines in order
  for line, parsed in line_data:
    if parsed:
      prefix, frame_num, addr = parsed
      function, file_line = resolved[addr]
      print(format_symbolized_line(prefix, frame_num, addr, function, file_line), end='')
    else:
      print(line, end='')

def parse_symbolizable_line(line):
  """Parse a symbolizable line and return (prefix, frame_num, addr)"""
  m = re.match(r"(\[ *\d*\])? *#(\d*) (0x[a-zA-Z0-9]*)\s*$", line)
  if m:
    prefix = m.group(1) if m.group(1) else ''
    frame_num = m.group(2)
    addr = m.group(3)
    return (prefix, frame_num, addr)
  return None

def is_symbolizable_line(line):
  """Check if a line contains an address that should be symbolized"""
  return parse_symbolizable_line(line) is not None

def read_chunk(infile, max_normal_lines, max_symbolizable_lines):
  """Read a chunk of lines from stdin with appropriate batching logic"""
  chunk = []
  max_lines = max_normal_lines

  while True:
    if len(chunk) >= max_lines:
      break

    line = infile.readline()
    if not line:
      # EOF reached
      break

    chunk.append(line)

    # If we see a symbolizable line, switch to symbolizable batching mode.
    if is_symbolizable_line(line):
      max_lines = max_symbolizable_lines

  return chunk

TOOL_PREFIX = get_tool_prefix()

if len(sys.argv) > 2 or (len(sys.argv) == 2 and sys.argv[1] != "--batch"):
  print("Usage: %s [--batch]" % sys.argv[0], file=sys.stderr)
  sys.exit(1)

batch_size = BATCH_SIZE if '--batch' in sys.argv else 1

# Reopen stdin with errors=replace --- the logs will sometimes contain garbage
# bytes (e.g. if an invalid string is read from raw memory in a failing test),
# which will not be decodable as UTF-8.  This prevents the script from stopping
# if those are encountered.
sys.stdin.reconfigure(errors='replace')

try:
  while True:
    chunk = read_chunk(sys.stdin, 1, batch_size)

    if not chunk:
      # EOF reached
      break

    process_line_buffer(TOOL_PREFIX, chunk)
    sys.stdout.flush()

except KeyboardInterrupt:
  sys.stdout.flush()
  pass
except IOError as e:
  if e.errno == errno.EPIPE:
    sys.exit(0)
  raise e
