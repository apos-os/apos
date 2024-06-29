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

#include "common/hash.h"
#include "common/crc.h"
#include "common/kprintf.h"
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
}

static void crc_test(void) {
  KTEST_BEGIN("CRC32 test");
  KEXPECT_EQ(0xe8b7be43, crc32((const uint8_t*)"a", 1, CRC32_NET_POLY));
  KEXPECT_EQ(0xcbf43926, crc32((const uint8_t*)"123456789", 9, CRC32_NET_POLY));
  KEXPECT_EQ(0xd202ef8d, crc32((const uint8_t*)"\0", 1, CRC32_NET_POLY));
  KEXPECT_EQ(0xed82cd11, crc32((const uint8_t*)"abcd", 4, CRC32_NET_POLY));
  KEXPECT_EQ(0xeb8eba67, crc32((const uint8_t*)"xyz", 3, CRC32_NET_POLY));
  KEXPECT_EQ(0, crc32((const uint8_t*)"", 0, CRC32_NET_POLY));
}

void hash_test(void) {
  KTEST_SUITE_BEGIN("hash test");

  basic_fnv_test();
  fnv_array_test();
  fnv_concat_test();

  KTEST_SUITE_BEGIN("MD5 hash test");
  md5_test();

  KTEST_SUITE_BEGIN("CRC tests");
  crc_test();
}
