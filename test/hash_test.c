// Copyright 2014 Andrew Oates.  All Rights Reserved.
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

#include <stdint.h>

#include "common/endian.h"
#include "common/hash.h"
#include "common/crc.h"
#include "common/kprintf.h"
#include "common/siphash.h"
#include "test/hamlet.h"
#include "test/ktest.h"

static void basic_fnv_test(void) {
  KTEST_BEGIN("fnv_hash(): basic test");
  KEXPECT_EQ(1268118805, fnv_hash(0));
  KEXPECT_EQ(4218009092, fnv_hash(1));
  KEXPECT_EQ(3958272823, fnv_hash(2));
  KEXPECT_EQ(794109580, fnv_hash(12345678));

  KEXPECT_EQ(0x9be17165, fnv_hash64(0));
  KEXPECT_EQ(0x3e801244, fnv_hash64(1));
  KEXPECT_EQ(0x2804678d, fnv_hash64(0x0807060504030201));

  // TODO(endian): determine if this is proper behavior w.r.t. endianness and
  // fix if not.  Should this be endian-agnostic?
  uint32_t val32 = 0;
  KEXPECT_EQ(1268118805, fnv_hash_array(&val32, sizeof(uint32_t)));
  val32 = 1;
  KEXPECT_EQ(4218009092, fnv_hash_array(&val32, sizeof(uint32_t)));
  val32 = 2;
  KEXPECT_EQ(3958272823, fnv_hash_array(&val32, sizeof(uint32_t)));
  val32 = 12345678;
  KEXPECT_EQ(794109580, fnv_hash_array(&val32, sizeof(uint32_t)));

  uint64_t val64 = 0;
  KEXPECT_EQ(0x9be17165, fnv_hash_array(&val64, sizeof(uint64_t)));
  val64 = 1;
  KEXPECT_EQ(0x3e801244, fnv_hash_array(&val64, sizeof(uint64_t)));
  val64 = 0x0807060504030201;
  KEXPECT_EQ(0x2804678d, fnv_hash_array(&val64, sizeof(uint64_t)));

  KTEST_BEGIN("fnv_hash_addr(): basic test");
#if ARCH_IS_64_BIT
    addr_t addr = 0x12345678abcdef12;
    KEXPECT_EQ(fnv_hash64(addr), fnv_hash_addr(addr));
#else
    addr_t addr = 0x12345678;
    KEXPECT_EQ(fnv_hash(addr), fnv_hash_addr(addr));
#endif
}

static void fnv_array_test(void) {
  KTEST_BEGIN("fnv_hash_array(): basic test");

  for (uint32_t i = 0; i < 10; ++i) {
    KEXPECT_EQ(fnv_hash(i), fnv_hash_array(&i, sizeof(uint32_t)));
  }

  KEXPECT_EQ(0xd58b3fa7, fnv_hash_array("hello world", 11));
  KEXPECT_EQ(0x02186e67, fnv_hash_array("HELLO WORLD", 11));
  KEXPECT_EQ(0x65c5fd60, fnv_hash_array("abcd12345", 9));

  KEXPECT_EQ(0xd58b3fa7, fnv_hash_string("hello world"));
  KEXPECT_EQ(0xd58b3fa7, fnv_hash_string("hello world\0x"));
  KEXPECT_EQ(0x02186e67, fnv_hash_string("HELLO WORLD\0yyy"));
  KEXPECT_EQ(0x65c5fd60, fnv_hash_string("abcd12345"));
}

static void fnv_concat_test(void) {
  KTEST_BEGIN("fnv_hash_concat(): basic test");

  KEXPECT_NE(fnv_hash_concat(1, 2), 1);
  KEXPECT_NE(fnv_hash_concat(1, 2), fnv_hash(1));
  KEXPECT_NE(fnv_hash_concat(1, 2), 2);
  KEXPECT_NE(fnv_hash_concat(1, 2), fnv_hash(2));
  KEXPECT_NE(fnv_hash_concat(1, 2), fnv_hash_concat(2, 1));

  uint32_t x = 0;
  for (int i = 0; i < 10; ++i) {
    uint32_t old_x = x;
    x = fnv_hash_concat(x, i);
    KEXPECT_NE(0, x);
    KEXPECT_NE(old_x, x);
  }
}

static void basic_fnv64_test(void) {
  KTEST_BEGIN("fnv64_hash(): basic test");
  KEXPECT_EQ(0xa8c7f832281a39c5, fnv64_hash(htob64(0)));
  KEXPECT_EQ(0xa8c7f732281a3812, fnv64_hash(htob64(1)));
  KEXPECT_EQ(0xa8c7f632281a365f, fnv64_hash(htob64(2)));
  KEXPECT_EQ(0x659787be488521d5, fnv64_hash(htob64(0x12345678)));
  KEXPECT_EQ(0xcfa2bd135d067fed, fnv64_hash(htob64(0x12345678abcdef01)));
}

static void fnv64_array_test(void) {
  KTEST_BEGIN("fnv64_hash_array(): basic test");

  for (uint64_t i = 0; i < 10; ++i) {
    KEXPECT_EQ(fnv64_hash(i), fnv64_hash_array(&i, sizeof(uint64_t)));
  }

  for (uint64_t i = UINT64_MAX - 10; i < UINT64_MAX; ++i) {
    KEXPECT_EQ(fnv64_hash(i), fnv64_hash_array(&i, sizeof(uint64_t)));
  }

  KEXPECT_EQ(0x779a65e7023cd2e7, fnv64_hash_array("hello world", 11));
  KEXPECT_EQ(0x59f5f65ebaf8b367, fnv64_hash_array("HELLO WORLD", 11));
  KEXPECT_EQ(0x4c344629608d5f40, fnv64_hash_array("abcd12345", 9));

  KEXPECT_EQ(0xaf63bd4c8601b7df, fnv64_hash_array("\0", 1));
  KEXPECT_EQ(0xaf63bc4c8601b62c, fnv64_hash_array("\1", 1));
  KEXPECT_EQ(0x086f8007b51f1073, fnv64_hash_array("\x12\x34", 2));
  KEXPECT_EQ(0x7486b218c3c86edf, fnv64_hash_array("\x12\x34\x56", 3));

  KEXPECT_EQ(0x7C930E439CD83087, fnv64_hash_concat(fnv64_hash_array("abc", 3),
                                                   fnv64_hash_array("def", 3)));
  KEXPECT_EQ(0x89F30B7243873775, fnv64_hash_concat(fnv64_hash_array("abc", 3),
                                                   fnv64_hash_array("deg", 3)));
  KEXPECT_EQ(0xA83DC77212AD9BED, fnv64_hash_concat(fnv64_hash_array("abd", 3),
                                                   fnv64_hash_array("def", 3)));
}

const char* get_md5_hash_n(const char* str, int len) {
  static char md5_str[8 * 4 + 1];
  uint8_t md5[16];
  md5_hash(str, len, md5);
  for (int i = 0; i < 16; ++i) {
    ksprintf(md5_str + i * 2, "%02x", md5[i]);
  }
  return md5_str;
}

const char* get_md5_hash(const char* str) {
  return get_md5_hash_n(str, kstrlen(str));
}

static void md5_test(void) {
  KTEST_BEGIN("MD5 empty string");
  KEXPECT_STREQ("d41d8cd98f00b204e9800998ecf8427e", get_md5_hash(""));

  KTEST_BEGIN("MD5 basic short strings");
  KEXPECT_STREQ("900150983cd24fb0d6963f7d28e17f72", get_md5_hash("abc"));
  KEXPECT_STREQ("7ac66c0f148de9519b8bd264312c4d64", get_md5_hash("abcdefg"));

  KTEST_BEGIN("MD5 hamlet test (55 bytes)");
  KEXPECT_STREQ("1c324e7bc068c218b628d35a3529289a",
                get_md5_hash_n(kHamlet, 55));

  KTEST_BEGIN("MD5 hamlet test (56 bytes)");
  KEXPECT_STREQ("f4d6cdad4ffc09460cc508872b448dec",
                get_md5_hash_n(kHamlet, 56));

  KTEST_BEGIN("MD5 hamlet test (57 bytes)");
  KEXPECT_STREQ("017f3d7432a8b53560929cfca93c0341",
                get_md5_hash_n(kHamlet, 57));

  KTEST_BEGIN("MD5 hamlet test (64 bytes)");
  KEXPECT_STREQ("9d99a0b1c317910ea2e011f2b1297cfd",
                get_md5_hash_n(kHamlet, 64));

  KTEST_BEGIN("MD5 hamlet test (63 bytes)");
  KEXPECT_STREQ("e4e0bdc2b5ad9e9c895364e6f8191cc9",
                get_md5_hash_n(kHamlet, 63));

  KTEST_BEGIN("MD5 hamlet test (65 bytes)");
  KEXPECT_STREQ("94baa475b8d7577fdc1acee7663e19f9",
                get_md5_hash_n(kHamlet, 65));

  KTEST_BEGIN("MD5 hamlet test (100 bytes)");
  KEXPECT_STREQ("cddef6e346ce4e329df261ab9caefeb1",
                get_md5_hash_n(kHamlet, 100));

  KTEST_BEGIN("MD5 hamlet test (119 bytes)");
  KEXPECT_STREQ("de58a5d0cf2ff4ed380e5836245b43f7",
                get_md5_hash_n(kHamlet, 119));

  KTEST_BEGIN("MD5 hamlet test (120 bytes)");
  KEXPECT_STREQ("1542adc6068cb989ea296a5c94a09b2c",
                get_md5_hash_n(kHamlet, 120));

  KTEST_BEGIN("MD5 hamlet test (127 bytes)");
  KEXPECT_STREQ("f514106775bff844045c1f103d8af95c",
                get_md5_hash_n(kHamlet, 127));

  KTEST_BEGIN("MD5 hamlet test (128 bytes)");
  KEXPECT_STREQ("50eb22e61ba28cf5666b3d0c9bd335fd",
                get_md5_hash_n(kHamlet, 128));

  KTEST_BEGIN("MD5 hamlet test (129 bytes)");
  KEXPECT_STREQ("62d13cb67e41501e50c276f62fe0d17e",
                get_md5_hash_n(kHamlet, 129));

  KTEST_BEGIN("MD5 hamlet test (200 bytes)");
  KEXPECT_STREQ("5ba05d4bf82d0cba0048ef0a4d82b621",
                get_md5_hash_n(kHamlet, 200));

  KTEST_BEGIN("MD5 hamlet test (1000 bytes)");
  KEXPECT_STREQ("7930a15bee177618802514e57effbc71",
                get_md5_hash_n(kHamlet, 1000));

  KTEST_BEGIN("MD5 hamlet test (all data)");
  KEXPECT_EQ(kHamletSize, kstrlen(kHamlet) + 1);
  KEXPECT_STREQ("4a0b0f8a18f73a3280c33539a834333e",
                get_md5_hash_n(kHamlet, kHamletSize));
}

static void crc_test(void) {
  KTEST_BEGIN("CRC32 test");
  KEXPECT_EQ(0xe8b7be43, crc32((const uint8_t*)"a", 1, CRC32_NET_POLY));
  KEXPECT_EQ(0xcbf43926, crc32((const uint8_t*)"123456789", 9, CRC32_NET_POLY));
  KEXPECT_EQ(0xd202ef8d, crc32((const uint8_t*)"\0", 1, CRC32_NET_POLY));
  KEXPECT_EQ(0xed82cd11, crc32((const uint8_t*)"abcd", 4, CRC32_NET_POLY));
  KEXPECT_EQ(0xeb8eba67, crc32((const uint8_t*)"xyz", 3, CRC32_NET_POLY));
  KEXPECT_EQ(0, crc32((const uint8_t*)"", 0, CRC32_NET_POLY));

  KEXPECT_EQ(0x3d8212e8, ether_crc32((const uint8_t*)"a", 1));
  KEXPECT_EQ(0x9b63d02c, ether_crc32((const uint8_t*)"123456789", 9));
  KEXPECT_EQ(0x4e08bfb4, ether_crc32((const uint8_t*)"\0", 1));
  KEXPECT_EQ(0x774cbe48, ether_crc32((const uint8_t*)"abcd", 4));
  KEXPECT_EQ(0x19a28e28, ether_crc32((const uint8_t*)"xyz", 3));
  KEXPECT_EQ(0xffffffff, ether_crc32((const uint8_t*)"", 0));

  uint8_t mac[] = {0x33, 0x33, 0xff, 0x00, 0x00, 0x01};
  KEXPECT_EQ(0x76fb0ac1, ether_crc32(mac, 6));
}

typedef struct {
  const uint8_t key[16];
  const char* input;
  int len;
  uint64_t hash;
} siphash_test_t;

static const siphash_test_t kSiphashTests[] = {
    {
        {0x5a, 0x17, 0x4c, 0x22, 0xc4, 0x87, 0xd0, 0xc5, 0xc1, 0x16, 0x1e, 0x57,
         0x0d, 0x10, 0xd1, 0x45},
        "",
        0,
        0x9f06a76d8ae7ff05,
    },
    {
        {0xd5, 0x67, 0x45, 0x46, 0x9a, 0xe4, 0x27, 0x34, 0xc2, 0xad, 0x87, 0xe7,
         0xc1, 0x3e, 0xa1, 0x01},
        "\x3c",
        1,
        0x9698cd8e2620362f,
    },
    {
        {0xcc, 0x7c, 0x78, 0xae, 0x24, 0xca, 0x10, 0x6c, 0x5d, 0x77, 0x17, 0x42,
         0xb5, 0x30, 0xcb, 0xce},
        "\x6c\xfb",
        2,
        0xa94c8f359a6034d0,
    },
    {
        {0xc8, 0xde, 0x6d, 0x12, 0x04, 0x62, 0x73, 0x9b, 0x29, 0xb2, 0x59, 0x13,
         0xf7, 0x5f, 0x8b, 0xe4},
        "\x8b\xff\x10",
        3,
        0x5f12329867deb530,
    },
    {
        {0xc4, 0x35, 0xd9, 0x5c, 0x06, 0x08, 0x5d, 0xc2, 0x60, 0x60, 0xe4, 0x88,
         0xf0, 0x69, 0x10, 0x13},
        "\xf5\x75\x79\x1b",
        4,
        0x38824fa193583e1c,
    },
    {
        {0x5d, 0x58, 0x53, 0x67, 0x5b, 0xbe, 0x37, 0xb0, 0x03, 0x4e, 0x01, 0x9c,
         0x87, 0x03, 0xbb, 0xea},
        "\x20\xbe\x54\xd5\x83",
        5,
        0x5586f5ed0a52d560,
    },
    {
        {0x77, 0xfd, 0xc2, 0x46, 0x7c, 0xb5, 0xcf, 0xad, 0xba, 0x4d, 0xcb, 0x02,
         0xf0, 0x8d, 0x5d, 0xe0},
        "\x58\xff\x9d\x2a\xf7\x1e",
        6,
        0xacc2bf8eb5308b5b,
    },
    {
        {0x3f, 0x1a, 0xbc, 0x8a, 0x74, 0x47, 0x0e, 0x69, 0x7a, 0xad, 0xe7, 0xbb,
         0x40, 0x9d, 0x8c, 0x36},
        "\x2a\x0d\x12\xd9\x9b\x8c\x10",
        7,
        0x2349992cbb601e73,
    },
    {
        {0xad, 0x97, 0x76, 0x40, 0xb6, 0x90, 0x2d, 0xb5, 0xfb, 0x05, 0xc3, 0x5b,
         0xde, 0x85, 0xe2, 0x21},
        "\x33\x6d\xdb\xba\x25\xfc\x15\xfd",
        8,
        0xc7a610c0743b7f8c,
    },
    {
        {0x9e, 0xeb, 0x5f, 0x0c, 0xe1, 0x54, 0x55, 0x97, 0xc9, 0x3f, 0xcd, 0x23,
         0x6e, 0x02, 0x2d, 0xf9},
        "\x12\x35\x69\xd0\xa5\x3d\x53\x99\xcf",
        9,
        0x7f25736f962974ce,
    },
    {
        {0x56, 0xd9, 0xec, 0xda, 0x63, 0x45, 0x12, 0x7a, 0xdb, 0xf7, 0x9e, 0x4e,
         0xc0, 0x87, 0x11, 0x16},
        "\xb4\x72\xf5\x65\xc1\x37\x0a\x62\x0c\x66",
        10,
        0x3f3acf72be80cb20,
    },
    {
        {0x4b, 0x5a, 0x67, 0xfa, 0xd0, 0xb4, 0xc6, 0xdd, 0x41, 0x65, 0x6e, 0x79,
         0xe4, 0x7e, 0x4c, 0xcc},
        "\x31\x7e\x7e\xf6\x4c\x39\xcf\x11\x12\x12\xcd",
        11,
        0x4c8ee337c7103c0b,
    },
    {
        {0xe0, 0xe0, 0x43, 0x22, 0xfb, 0x57, 0xcf, 0x43, 0xfb, 0x68, 0x09, 0xa3,
         0x3d, 0x39, 0x25, 0x65},
        "\xa7\x83\xac\xa5\x73\xcb\x07\xe8\x28\x29\xeb\x47",
        12,
        0x3d5ca090c68d3a94,
    },
    {
        {0x28, 0x95, 0xc3, 0x87, 0x88, 0xe0, 0x64, 0x54, 0x15, 0x84, 0xf2, 0x22,
         0x90, 0x0a, 0x45, 0xfb},
        "\x63\x81\x89\x4b\x79\x47\xf3\xcd\xb6\xec\xa1\xe8\xc5",
        13,
        0x8ee7682323bbf06b,
    },
    {
        {0xc3, 0xa0, 0xb4, 0xea, 0x71, 0xd4, 0xe8, 0x24, 0x45, 0x9a, 0xca, 0xc0,
         0xaa, 0x2c, 0xaa, 0x9d},
        "\x6a\x92\x57\x06\x5f\x99\x1f\x36\xba\x17\x5e\xc1\x77\xb8",
        14,
        0x078b76ac3dc840e2,
    },
    {
        {0x56, 0xe7, 0xc5, 0xdc, 0x7b, 0xa9, 0xc3, 0x70, 0x95, 0x11, 0x7d, 0x3b,
         0x78, 0xb6, 0xbe, 0x0c},
        "\xd9\xa8\x40\x2b\xc9\x30\x3b\x5a\x67\xc3\xaa\x0f\x19\x75\xac",
        15,
        0xf5fc32c55915e9ff,
    },
    {
        {0xff, 0xcd, 0x0c, 0xa3, 0x1d, 0xbb, 0x4c, 0x0a, 0x64, 0xbc, 0xe8, 0x3d,
         0x4a, 0x87, 0x6e, 0x2f},
        "\x4c\x50\xfc\xa6\x88\xdc\xc3\x4a\x62\xbf\x77\x55\x4a\xf2\x2f\xca",
        16,
        0x9e266efdc2b55efa,
    },
    {
        {0xa3, 0x58, 0xac, 0xb4, 0x75, 0xfe, 0x3a, 0x54, 0x5a, 0xba, 0x17, 0x2e,
         0x6a, 0x2e, 0x60, 0x6b},
        "\xe2\xe6\x00\x7a\xda\xc9\x76\x73\x6a\x22\x2a\xd2\xa6\x07\xd4\xd1\x5d",
        17,
        0xc4bb7312a7d39486,
    },
    {
        {0xcc, 0x61, 0x1d, 0x04, 0x30, 0x67, 0xa9, 0x9c, 0xb5, 0x57, 0x2b, 0xb0,
         0x12, 0x1b, 0xea, 0xc8},
        "\x74\x28\xcf\xc5\xfd\x76\xf0\xff\xc5\x9a\x21\x6b\x14\x25\x76\xd9\xee"
        "\x5d",
        18,
        0x67dc4aa8a52069df,
    },
    {
        {0x19, 0xc4, 0x41, 0x28, 0xe6, 0x1c, 0x99, 0x2e, 0x62, 0x5a, 0x11, 0x87,
         0x03, 0x65, 0x66, 0xb5},
        "\xf6\xb8\xf9\x42\x2f\x6e\xda\x5c\x70\x99\x97\x37\x57\x31\x42\xbd\x0d"
        "\x50\x3f",
        19,
        0x35d6199bb8b26627,
    },
    {
        {0xcc, 0x69, 0x0d, 0x64, 0xcb, 0xbd, 0x67, 0x66, 0xaf, 0x28, 0xd5, 0xe8,
         0x80, 0x98, 0x04, 0xe2},
        "\x80\xb9\xe1\x57\x66\xec\xf0\xfd\x98\x86\x58\x70\x13\x28\xa2\x66\x22"
        "\x05\x28\xf9",
        20,
        0x8da47f7d2c8a24b9,
    },
    {
        {0xd0, 0x97, 0xc3, 0x27, 0x07, 0xd1, 0x11, 0x35, 0x8a, 0x8f, 0x64, 0x70,
         0xc4, 0xbb, 0xd3, 0xbb},
        "\x4a\x17\x4e\xdf\x08\x6a\x54\x06\xf3\x6a\xa2\x0f\x1d\xc5\xf8\x54\xdf"
        "\x26\x4e\xc1\x59",
        21,
        0x8dab02709978b647,
    },
    {
        {0x79, 0xa0, 0x47, 0x07, 0x1e, 0xdd, 0x76, 0xcc, 0x63, 0x4f, 0x95, 0x10,
         0xdd, 0x01, 0x13, 0xc7},
        "\x24\x7b\xa7\x24\x55\xb9\xa9\x7d\xab\xab\x69\x05\xb0\xa1\x22\x76\x35"
        "\xf7\x9f\x3e\x53\x0e",
        22,
        0x1364c8043fb9baac,
    },
    {
        {0xb3, 0x09, 0x2a, 0xcd, 0xd6, 0x02, 0x32, 0x15, 0x70, 0x1a, 0xa9, 0xc9,
         0x9a, 0xe4, 0xe2, 0x18},
        "\xce\x36\xb7\x55\x30\x02\x73\xc2\x28\x05\xee\xbd\xfe\x7d\xad\xb5\x9f"
        "\xff\x0b\xf8\x16\x7f\xba",
        23,
        0xc8e50f39c0605ecb,
    },
    {
        {0xdb, 0x6c, 0x7c, 0xe7, 0x46, 0xa0, 0x43, 0x1f, 0x82, 0x69, 0x40, 0x7f,
         0x8c, 0x35, 0xa4, 0xcd},
        "\x40\xdb\xed\xc0\xf4\xc3\x51\xa6\xff\xc0\x58\xa2\xff\x63\x79\x44\x19"
        "\xb1\xc2\xec\xb4\x75\x9f\x6d",
        24,
        0x9f46bd8f53a03217,
    },
    {
        {0x11, 0x03, 0x01, 0x07, 0x1f, 0x66, 0x76, 0xfc, 0x2a, 0xe4, 0x1a, 0x5c,
         0xea, 0x83, 0xb1, 0x0f},
        "\x79\x47\xc7\xe5\x5c\x5f\xe0\xfd\x58\x4a\xde\x5a\x30\xf8\xaf\x69\xcf"
        "\xbc\xc4\x82\x5c\xa4\xe4\x5f\xd8",
        25,
        0x7305e77b0e3dd8bb,
    },
    {
        {0x97, 0x6c, 0x2e, 0xe4, 0x77, 0x83, 0x76, 0x6e, 0xa8, 0x23, 0x50, 0x01,
         0xf6, 0x5d, 0x25, 0x6b},
        "\x91\x2b\xe0\xef\x8e\x0e\x7b\xec\xfa\x17\x6e\xd4\x00\x6e\xe8\xf2\xe7"
        "\x71\x07\xf0\x22\xe4\x23\x51\xcc\x20",
        26,
        0x2f05ddca521adcf1,
    },
    {
        {0x58, 0xb1, 0xde, 0x6e, 0x33, 0xff, 0xea, 0x22, 0x8e, 0x14, 0x4b, 0x4f,
         0x25, 0xe5, 0x76, 0x2e},
        "\x02\xe8\xb8\x93\x12\x47\x9f\x1b\x0a\x6d\xa0\xf7\xf3\x5e\x6c\xcb\x50"
        "\xad\xe3\x22\xe7\x0b\xa2\xf5\xb0\xa3\x54",
        27,
        0xdd0547e80e8505e1,
    },
    {
        {0xbc, 0x57, 0xf2, 0x8c, 0x8f, 0x46, 0x1d, 0x97, 0x14, 0xb4, 0x8c, 0x08,
         0x71, 0x64, 0xa6, 0x95},
        "\x99\x0c\xeb\x64\x62\x8b\xba\xfa\x3c\x0c\x4b\xda\xbf\x46\x5a\x19\xd0"
        "\x75\xfb\x66\x91\x8d\xd2\x40\xeb\xef\x17\x6f",
        28,
        0x7ce492853fc22eb8,
    },
    {
        {0x16, 0xc2, 0xff, 0xc4, 0xe0, 0x3d, 0x5f, 0x17, 0x06, 0x4f, 0x22, 0xfe,
         0x05, 0x12, 0xee, 0xbc},
        "\x42\xe7\x8f\x02\x9e\xaa\xa1\x47\x42\x68\xd5\x34\xd1\x54\x2e\x60\x19"
        "\xaf\x7c\x31\x1b\x70\xa3\xb8\x0d\x89\xfc\x83\x94",
        29,
        0x5830bdb3f6cdbf80,
    },
    {
        {0x54, 0x6c, 0xec, 0x4e, 0xc1, 0xcc, 0xdd, 0x1d, 0xec, 0x16, 0xff, 0xd6,
         0x84, 0xfb, 0xa1, 0x60},
        "\x36\xfa\x97\xe2\xd2\x0f\x91\xa5\x63\x89\xc8\x4d\x3c\x26\x70\xc2\x5a"
        "\xfd\x2d\x55\x1d\xe8\x93\x0c\x73\x5f\x30\xdc\x0f\x8e",
        30,
        0xcc29ae6a40051fa9,
    },
    {
        {0xdc, 0x04, 0x25, 0x5c, 0x12, 0x14, 0x07, 0x7c, 0x60, 0xed, 0x57, 0xc0,
         0x07, 0x19, 0xc4, 0xae},
        "\xf6\xed\xdb\x62\x22\x5c\x75\xe4\x76\x36\x58\x7d\x99\x2a\xbb\x31\xfb"
        "\x14\x29\xcf\x0e\x4b\xdf\x7c\xa7\x61\x08\x33\xc6\xc1\x45",
        31,
        0x8959c817d89057b1,
    },
    {
        {0x66, 0xfa, 0x7b, 0x74, 0xc5, 0xd1, 0x12, 0x04, 0x4e, 0x6e, 0x26, 0xa8,
         0xf0, 0x56, 0x67, 0x2e},
        "\x9c\x30\x3c\x50\x97\x35\x8b\x46\x71\xf2\xb2\x82\xd2\x28\x6c\xcb\x99"
        "\x25\xe2\x27\x17\xf3\xe1\xbb\x16\xa2\xa7\xf0\x88\xc8\x9e\xfb",
        32,
        0xef44eb07b3dabf20,
    },
    {
        {0xe6, 0x8c, 0x0b, 0x8b, 0x0f, 0xc1, 0x94, 0x40, 0x2a, 0x07, 0x40, 0x69,
         0xfa, 0x79, 0xbc, 0xc9},
        "\x68\x74\x0d\xd3\x2b\x54\xab\x57\x31\x3b\x7a\xba\x72\x12\xee\xae\xed"
        "\xcd\x00\xfc\x34\xb5\xa2\x95\xc3\x74\x23\x61\xac\xb4\x50\xc3\x31",
        33,
        0x31c38d85506f95e2,
    },
    {
        {0x5a, 0x9b, 0xda, 0x07, 0x5c, 0x2c, 0x37, 0x56, 0xbb, 0x03, 0x63, 0x7b,
         0x83, 0x3a, 0x2c, 0x7c},
        "\x0a\x20\xae\x05\x07\x7a\x27\x75\xac\xcf\x3e\x93\x19\x7c\x2c\xbe\x58"
        "\xec\x0c\x8c\xb2\xd6\x66\xa6\xd1\xc5\xab\x8f\x6a\x88\x92\x1b\x33\xa6",
        34,
        0x83ac7417ef2f78cc,
    },
    {
        {0xbd, 0xdb, 0x52, 0x9b, 0xeb, 0x2c, 0x89, 0xee, 0x5f, 0x3e, 0x6b, 0x91,
         0xc7, 0x86, 0xf7, 0xbe},
        "\xa9\x63\xb7\xe8\xa6\xab\x9e\xbc\xe9\x13\xd3\x9a\xf0\x35\x54\x0d\x11"
        "\x72\x48\x8c\x29\xb8\x52\x17\xed\xf0\x21\x43\xc2\x31\x83\xda\x52\xa3"
        "\xba",
        35,
        0x87bfacf3844aa239,
    },
    {{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, NULL, 0, 0},
};

static void siphash_test(void) {
  KTEST_BEGIN("Basic SipHash tests");
  // Test case from the SipHash paper Appendix A:
  uint64_t key[2] = {0x0706050403020100, 0x0f0e0d0c0b0a0908};
  uint8_t data[15] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                      0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e};
  KEXPECT_EQ(0xa129ca6149be45e5, siphash_2_4(key, data, 15));

  const uint8_t key2[16] = {
      0x5a, 0x17, 0x4c, 0x22, 0xc4, 0x87, 0xd0, 0xc5,
      0xc1, 0x16, 0x1e, 0x57, 0x0d, 0x10, 0xd1, 0x45,
  };
  kmemcpy(key, key2, 16);
  KEXPECT_EQ(btoh64(0x9f06a76d8ae7ff05), siphash_2_4(key, "", 0));

  // Test cases borrowed from BoringSSL:
  // https://boringssl.googlesource.com/boringssl/+/master/crypto/siphash/siphash_tests.txt
  for (int i = 0; kSiphashTests[i].input != NULL; ++i) {
    kmemcpy(&key, &kSiphashTests[i].key, sizeof(uint64_t) * 2);
    uint64_t result =
        siphash_2_4(key, kSiphashTests[i].input, kSiphashTests[i].len);
    if (result != btoh64(kSiphashTests[i].hash)) {
      KLOG("SipHash test %i failed\n", i);
    }
    KEXPECT_EQ(btoh64(kSiphashTests[i].hash), result);
  }
}

void hash_test(void) {
  KTEST_SUITE_BEGIN("hash test");

  basic_fnv_test();
  fnv_array_test();
  fnv_concat_test();
  basic_fnv64_test();
  fnv64_array_test();

  KTEST_SUITE_BEGIN("MD5 hash test");
  md5_test();

  KTEST_SUITE_BEGIN("CRC tests");
  crc_test();

  KTEST_SUITE_BEGIN("SipHash tests");
  siphash_test();
}
