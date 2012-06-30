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


import re

codes = [
("'", "52", "F0,52"),
(",", "41", "F0,41"),
("-", "4E", "F0,4E"),
(".", "49", "F0,49"),
("/", "4A", "F0,4A"),
("0", "45", "F0,45"),
("1", "16", "F0,16"),
("2", "1E", "F0,1E"),
("3", "26", "F0,26"),
("4", "25", "F0,25"),
("5", "2E", "F0,2E"),
("6", "36", "F0,36"),
("7", "3D", "F0,3D"),
("8", "3E", "F0,3E"),
("9", "46", "F0,46"),
(";", "4C", "F0,4C"),
("=", "55", "F0,55"),
("A", "1C", "F0,1C"),
("APPS", "E0,2F", "E0,F0,2F"),
("B", "32", "F0,32"),
("BKSP", "66", "F0,66"),
("C", "21", "F0,21"),
("CAPS", "58", "F0,58"),
("D ARROW", "E0,72", "E0,F0,72"),
("D", "23", "F0,23"),
("DELETE", "E0,71", "E0,F0,71"),
("E", "24", "F0,24"),
("END", "E0,69", "E0,F0,69"),
("ENTER", "5A", "F0,5A"),
("ESC", "76", "F0,76"),
("F", "2B", "F0,2B"),
("F1", "05", "F0,05"),
("F10", "09", "F0,09"),
("F11", "78", "F0,78"),
("F12", "07", "F0,07"),
("F2", "06", "F0,06"),
("F3", "04", "F0,04"),
("F4", "0C", "F0,0C"),
("F5", "03", "F0,03"),
("F6", "0B", "F0,0B"),
("F7", "83", "F0,83"),
("F8", "0A", "F0,0A"),
("F9", "01", "F0,01"),
("G", "34", "F0,34"),
("H", "33", "F0,33"),
("HOME", "E0,6C", "E0,F0,6C"),
("I", "43", "F0,43"),
("INSERT", "E0,70", "E0,F0,70"),
("J", "3B", "F0,3B"),
("K", "42", "F0,42"),
("KP *", "7C", "F0,7C"),
("KP +", "79", "F0,79"),
("KP -", "7B", "F0,7B"),
("KP .", "71", "F0,71"),
("KP /", "E0,4A", "E0,F0,4A"),
("KP 0", "70", "F0,70"),
("KP 1", "69", "F0,69"),
("KP 2", "72", "F0,72"),
("KP 3", "7A", "F0,7A"),
("KP 4", "6B", "F0,6B"),
("KP 5", "73", "F0,73"),
("KP 6", "74", "F0,74"),
("KP 7", "6C", "F0,6C"),
("KP 8", "75", "F0,75"),
("KP 9", "7D", "F0,7D"),
("KP EN", "E0,5A", "E0,F0,5A"),
("L ALT", "11", "F0,11"),
("L ARROW", "E0,6B", "E0,F0,6B"),
("L CTRL", "14", "F0,14"),
("L GUI", "E0,1F", "E0,F0,1F"),
("L SHFT", "12", "F0,12"),
("L", "4B", "F0,4B"),
("M", "3A", "F0,3A"),
("N", "31", "F0,31"),
("NUM", "77", "F0,77"),
("O", "44", "F0,44"),
("P", "4D", "F0,4D"),
("PG DN", "E0,7A", "E0,F0,7A"),
("PG UP", "E0,7D", "E0,F0,7D"),
("Q", "15", "F0,15"),
("R ALT", "E0,11", "E0,F0,11"),
("R ARROW", "E0,74", "E0,F0,74"),
("R CTRL", "E0,14", "E0,F0,14"),
("R GUI", "E0,27", "E0,F0,27"),
("R SHFT", "59", "F0,59"),
("R", "2D", "F0,2D"),
("S", "1B", "F0,1B"),
("SCROLL", "7E", "F0,7E"),
("SPACE", "29", "F0,29"),
("T", "2C", "F0,2C"),
("TAB", "0D", "F0,0D"),
("U ARROW", "E0,75", "E0,F0,75"),
("U", "3C", "F0,3C"),
("V", "2A", "F0,2A"),
("W", "1D", "F0,1D"),
("X", "22", "F0,22"),
("Y", "35", "F0,35"),
("Z", "1A", "F0,1A"),
("[", "54", "F0,54"),
("\\", "5D", "F0,5D"),
("]", "5B", "F0,5B"),
("`", "0E", "F0,0E"),
]

trans = {
    "/": "SLASH",
    "\\": "BSLASH",
    "'": "QUOTE",
    ",": "COMMA",
    "-": "DASH",
    ".": "PERIOD",
    "*": "STAR",
    "[": "LBRACKET",
    "]": "RBRACKET",
    "(": "LPAREN",
    ")": "RPAREN",
    " ": "_",
    "=": "EQUALS",
    "`": "BACKTICK",
    ";": "SEMICOLON",
    "+": "PLUS",
    }

# First, reorder keys to put like keys together
codes_sorted = []
codes_sorted.extend([c for c in codes if
                  re.match('[0-9]$', c[0])])
codes_sorted.extend([c for c in codes if re.match('[a-zA-Z]$', c[0])])

# Handle L_* and R_* and U_* and D_*
for code in codes:
  m = re.match('[UL] (.*)', code[0])
  if m:
    other = {
        'L': 'R %s' % m.group(1),
        'U': 'D %s' % m.group(1)
        }[code[0][0]]
    codes_sorted.append(code)
    codes_sorted.extend([c for c in codes if c[0] == other])

# Keypad
codes_sorted.extend([c for c in codes if c[0].startswith('KP ')])
# F keys, sorted by number
fkeys = [c for c in codes if re.match('F[0-9]+', c[0])]
codes_sorted.extend(sorted(fkeys, key=lambda x: int(x[0][1:])))

# Anything else.
already_matched = set([c[0] for c in codes_sorted])
codes_sorted.extend([c for c in codes if c[0] not in already_matched])

assert len(codes_sorted) == len(codes)
codes = codes_sorted

i = 1
codes_annot = []
for key, make, brk in codes:
  name = key
  for k,v in trans.iteritems():
    name = name.replace(k, v)
  name = 'KEY_%s' % name
  universal_code = i
  i += 1
  codes_annot.append((key, make, brk, name, universal_code))


#######
# Now print #defines
print '#define NONE 0'
for _, _, _, name, code in codes_annot:
  print '#define %s %s' % (name, code)

#######
# Now create make/break mappings
def seq2str(seq):
  return ''.join(['\\x%s' % x for x in seq.split(',')])

# Make a sorted list of single-digit codes and their #define names.
pairs = []
extended_pairs = []
for key, make, brk, name, code in codes_annot:
  parts = make.split(',')
  if len(parts) == 1:
    assert(brk == 'F0,' + make)
    pairs.append((make, name))
  else:
    assert(len(parts) == 2)
    assert(parts[0] == 'E0')
    assert(brk == ','.join(['E0', 'F0', parts[1]]))
    extended_pairs.append((parts[1], name))

# Now print the list, filling in any blank spots.
print "\n\n"
def print_code_list(lst):
  current_code = 0
  lst.sort()
  for make, name in lst:
    while current_code < int('0x%s' % make, 16):
      print 'NONE, // %s' % hex(current_code)
      current_code += 1
    print '%s, // 0x%s' % (name, make)
    current_code += 1

print 'NORMAL'
print '######'
print_code_list(pairs)

print '\nEXTENDED'
print '######'
print_code_list(extended_pairs)
