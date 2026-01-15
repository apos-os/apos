// Copyright 2026 Andrew Oates.  All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// The generated object file has the following hash table:
/*
    Histogram for `.gnu.hash' bucket list length (total of 17 buckets):
     Length  Number     % of total  Coverage
          0  3          ( 17.6%)
          1  6          ( 35.3%)     18.8%
          2  5          ( 29.4%)     50.0%
          3  1          (  5.9%)     59.4%
          4  0          (  0.0%)     59.4%
          5  0          (  0.0%)     59.4%
          6  1          (  5.9%)     78.1%
          7  1          (  5.9%)    100.0%

   $ riscv64-pc-apos-gcc -o os/core/loader/testdata/gnu_hash_lib.so -shared \
      -Wl,--hash-style=gnu os/core/loader/testdata/gnu_hash_lib.c
   $ riscv64-pc-apos-objcopy --dump-section .gnu.hash=/tmp/gnuhash \
      os/core/loader/testdata/gnu_hash_lib.so

   $ xxd -e /tmp/gnuhash
   00000000: 00000011 00000007 00000004 00000008  ................
   00000010: 40600006 03008215 12828261 20120818  ..`@....a......
   00000020: 820b0006 08004048 0080107c 0a010426  ....H@..|...&...
   00000030: 00000007 00000009 0000000a 00000000  ................
   00000040: 00000010 00000012 00000014 00000016  ................
   00000050: 00000017 00000018 00000000 00000019  ................
   00000060: 0000001c 00000000 0000001e 0000001f  ................
   00000070: 00000026 d7d4d538 7c95d749 0f11c21f  &...8...I..|....
   00000080: 85700182 85700182 404d25d6 7c93eac2  ..p...p..%M@...|
   00000090: 1922b0e2 6ccde37d 7c92e3ba f149e47d  ..".}..l...|}.I.
   000000a0: 1a8adf90 6ccde391 0f76ccc4 f14a06c3  .......l..v...J.
   000000b0: f149f141 7c93ee91 0f11c117 f14a0650  A.I....|....P.J.
   000000c0: 1a91e028 1a8ae1fb 7c93eea6 f149f9c5  (..........|..I.
   000000d0: 068a5391 7c93eb46 00002f24 0b885c74  .S..F..|$/..t\..
   000000e0: 6be6d96a 7683cf44 19243822 7683cf45  j..kD..v"8$.E..v
   000000f0: 7c93ee99                             ...|
*/

// Bloom filter bits for each of these symbols:
// bloom bits:           'abeyancies' N: 0 mask: 0200000000200000
// bloom bits:                 'dram' N: 1 mask: 0000000000800200
// bloom bits:                'abele' N: 0 mask: 0000000040000004
// bloom bits:        'radioscopical' N: 2 mask: 0000000000000006
// bloom bits:             'mordancy' N: 2 mask: 0000000000000006
// bloom bits:             'aasvogel' N: 3 mask: 0000002000800000
// bloom bits:                 'aahs' N: 3 mask: 0000040000000004
// bloom bits:              'aaronic' N: 3 mask: 0001000400000000
// bloom bits:             'abeyance' N: 1 mask: 2000000800000000
// bloom bits:                 '_end' N: 2 mask: 0800000800000000
// bloom bits:               'abedge' N: 1 mask: 2000001000000000
// bloom bits:              'abelian' N: 2 mask: 0000000080020000
// bloom bits:             'abeyancy' N: 2 mask: 0000000800020000
// bloom bits:                'func3' N: 3 mask: 0000000000001010
// bloom bits:               'abelia' N: 3 mask: 0000000000000048
// bloom bits:               'abegge' N: 1 mask: 0002000000000001
// bloom bits:                 'abed' N: 2 mask: 0000400000020000
// bloom bits:                'abede' N: 0 mask: 0000000000400002
// bloom bits:               'abeles' N: 1 mask: 0000000000020040
// bloom bits:              'abeyant' N: 0 mask: 0000020100000000
// bloom bits:              'abelite' N: 3 mask: 0800000200000000
// bloom bits:                 'abey' N: 2 mask: 0000404000000000
// bloom bits:               'abeigh' N: 3 mask: 0200000000000020
// bloom bits:            'abeyances' N: 2 mask: 0000000000090000
// bloom bits:                 'aals' N: 1 mask: 0000080000000040
// bloom bits:               'gliosa' N: 0 mask: 0000801000000000
// bloom bits:                  'aam' N: 1 mask: 0010000010000000
// bloom bits:             'abelicea' N: 1 mask: 0000080002000000
// bloom bits:         'colloquizing' N: 1 mask: 0000000000008020
// bloom bits:              'aarrghh' N: 0 mask: 0100000400000000
// bloom bits:          'monologuist' N: 1 mask: 0000000000008020
// bloom bits:                 'abel' N: 2 mask: 0000400002000000
// bloom bits:                 'abcd' N: 1 mask: 0000400000008000
// bloom bits:                'func1' N: 3 mask: 0000000000001004
// bloom bits:    '_long_symbol_name' N: 1 mask: 2000000000000200
// bloom bits:                     '' N: 0 mask: 0000000000200020
// bloom bits:              'vivency' N: 1 mask: 0000000000800200

// These will collide in the GNU hash function.
// hash % 17 == 2
void mordancy(void) {}       // 0x85700182
void radioscopical(void) {}  // 0x85700182
void aahs(void) {}           // 0x7c93eac2
void aaronic(void) {}        // 0x1922b0e2
void aasvogel(void) {}       // 0x404d25d7

void func3(void) {}          // 0x0f76ccc4

// hash % 17 == 15:
void monologuist(void) {}    // 0x7683cf45
void colloquizing(void) {}   // 0x7683cf45
void gliosa(void) {}         // 0x00002f24
void aals(void) {}           // 0x7c93eb46
void aam(void) {}            // 0x0b885c74
void aarrghh(void) {}        // 0x19243822

// These hash-collide, but only putting one in the table.
void dram(void) {}           // 0x7c95d749
// void vivency(void) {}     // 0x7c95d749

// A bunch of other symbols to fill up the hash table.
void abed(void) {}           // 0x7c93ee91
void abede(void) {}          // 0x0f11c116
void abedge(void) {}         // 0xf149e47d
void abegge(void) {}         // 0xf149f140
void abey(void) {}           // 0x7c93eea6
void abeyance(void) {}       // 0x6ccde37d
void abeyances(void) {}      // 0x068a5390
void abeyancy(void) {}       // 0x6ccde391
void abeyancies(void) {}     // 0xd7d4d539
void abeyant(void) {}        // 0x1a91e029
void abeigh(void) {}         // 0xf149f9c5
void abel(void) {}           // 0x7c93ee99
void abele(void) {}          // 0x0f11c21e
void abeles(void) {}         // 0xf14a0651
void abelia(void) {}         // 0xf14a06c3
void abelian(void) {}        // 0x1a8adf91
void abelicea(void) {}       // 0x6be6d96b
void abelite(void) {}        // 0x1a8ae1fb
