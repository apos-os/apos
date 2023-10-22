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

#include "common/circbuf.h"
#include "test/ktest.h"

#define CBUF_SIZE 10
static void basic_test(void) {
  KTEST_BEGIN("circbuf: basic read and write");
  char cbuf_data[CBUF_SIZE + 1];
  cbuf_data[CBUF_SIZE] = '\0';

  circbuf_t cbuf;
  circbuf_init(&cbuf, cbuf_data, CBUF_SIZE);
  KEXPECT_EQ(&cbuf_data, cbuf.buf);
  KEXPECT_EQ(CBUF_SIZE, cbuf.buflen);
  KEXPECT_EQ(0, cbuf.pos);
  KEXPECT_EQ(0, cbuf.len);
  KEXPECT_EQ(CBUF_SIZE, circbuf_available(&cbuf));

  kmemset(cbuf_data, 'x', CBUF_SIZE);
  KEXPECT_EQ(3, circbuf_write(&cbuf, "abc", 3));
  KEXPECT_EQ(&cbuf_data, cbuf.buf);
  KEXPECT_EQ(CBUF_SIZE, cbuf.buflen);
  KEXPECT_EQ(0, cbuf.pos);
  KEXPECT_EQ(3, cbuf.len);
  KEXPECT_EQ(CBUF_SIZE - 3, circbuf_available(&cbuf));
  KEXPECT_STREQ("abcxxxxxxx", cbuf_data);

  char out_buf[50];
  kmemset(out_buf, 'X', 50);

  KEXPECT_EQ(3, circbuf_read(&cbuf, out_buf, 5));
  out_buf[5] = '\0';
  KEXPECT_EQ(&cbuf_data, cbuf.buf);
  KEXPECT_EQ(CBUF_SIZE, cbuf.buflen);
  KEXPECT_EQ(3, cbuf.pos);
  KEXPECT_EQ(0, cbuf.len);
  KEXPECT_STREQ("xxxxxxx", cbuf_data + 3);
  KEXPECT_STREQ("abcXX", out_buf);

  KTEST_BEGIN("circbuf: basic read wrapping");
  circbuf_init(&cbuf, cbuf_data, CBUF_SIZE);
  kstrcpy(cbuf_data, "0123456789");
  cbuf.pos = 7;
  cbuf.len = 8;

  KEXPECT_EQ(5, circbuf_read(&cbuf, out_buf, 5));
  out_buf[5] = '\0';
  KEXPECT_EQ(2, cbuf.pos);
  KEXPECT_EQ(3, cbuf.len);
  KEXPECT_STREQ("78901", out_buf);
  KEXPECT_EQ(CBUF_SIZE - 3, circbuf_available(&cbuf));

  KTEST_BEGIN("circbuf: basic write wrapping");
  kstrcpy(cbuf_data, "0123456789");
  cbuf.pos = 6;
  cbuf.len = 2;

  kstrcpy(out_buf, "abcde");
  KEXPECT_EQ(5, circbuf_write(&cbuf, out_buf, 5));
  KEXPECT_EQ(6, cbuf.pos);
  KEXPECT_EQ(7, cbuf.len);
  KEXPECT_STREQ("cde34567ab", cbuf_data);


  KTEST_BEGIN("circbuf: read wrapping and hits full buffer");
  kstrcpy(cbuf_data, "0123456789");
  cbuf.pos = 7;
  cbuf.len = 10;

  kmemset(out_buf, 'X', 50);
  KEXPECT_EQ(10, circbuf_read(&cbuf, out_buf, 50));
  out_buf[10] = '\0';
  KEXPECT_EQ(7, cbuf.pos);
  KEXPECT_EQ(0, cbuf.len);
  KEXPECT_STREQ("7890123456", out_buf);


  KTEST_BEGIN("circbuf: read wrapping reading all data (non-full buffer)");
  kstrcpy(cbuf_data, "0123456789");
  cbuf.pos = 7;
  cbuf.len = 8;

  kmemset(out_buf, 'X', 50);
  KEXPECT_EQ(8, circbuf_read(&cbuf, out_buf, 50));
  out_buf[8] = '\0';
  KEXPECT_EQ(5, cbuf.pos);
  KEXPECT_EQ(0, cbuf.len);
  KEXPECT_STREQ("78901234", out_buf);


  KTEST_BEGIN("circbuf: read wrapping from last element of buffer");
  kstrcpy(cbuf_data, "0123456789");
  cbuf.pos = 9;
  cbuf.len = 10;

  kmemset(out_buf, 'X', 50);
  KEXPECT_EQ(4, circbuf_read(&cbuf, out_buf, 4));
  out_buf[4] = '\0';
  KEXPECT_EQ(3, cbuf.pos);
  KEXPECT_EQ(6, cbuf.len);
  KEXPECT_STREQ("9012", out_buf);


  KTEST_BEGIN("circbuf: write wrapping empty to full");
  kstrcpy(cbuf_data, "0123456789");
  cbuf.pos = 7;
  cbuf.len = 0;

  kstrcpy(out_buf, "abcdefghijklmnopqrstuvwxyz");
  KEXPECT_EQ(10, circbuf_write(&cbuf, out_buf, 26));
  out_buf[10] = '\0';
  KEXPECT_EQ(7, cbuf.pos);
  KEXPECT_EQ(10, cbuf.len);
  KEXPECT_STREQ("defghijabc", cbuf_data);


  KTEST_BEGIN("circbuf: write wrapping non-empty to full");
  kstrcpy(cbuf_data, "0123456789");
  cbuf.pos = 6;
  cbuf.len = 2;

  KEXPECT_EQ(8, circbuf_write(&cbuf, out_buf, 26));
  out_buf[8] = '\0';
  KEXPECT_EQ(6, cbuf.pos);
  KEXPECT_EQ(10, cbuf.len);
  KEXPECT_STREQ("cdefgh67ab", cbuf_data);


  KTEST_BEGIN("circbuf: write wrapping from last element of buffer");
  kstrcpy(cbuf_data, "0123456789");
  cbuf.pos = 9;
  cbuf.len = 3;

  KEXPECT_EQ(4, circbuf_write(&cbuf, out_buf, 4));
  KEXPECT_EQ(9, cbuf.pos);
  KEXPECT_EQ(7, cbuf.len);
  KEXPECT_STREQ("01abcd6789", cbuf_data);


  KTEST_BEGIN("circbuf: write wrapping from last element of buffer B");
  kstrcpy(cbuf_data, "0123456789");
  cbuf.pos = 9;
  cbuf.len = 0;

  KEXPECT_EQ(4, circbuf_write(&cbuf, out_buf, 4));
  KEXPECT_EQ(9, cbuf.pos);
  KEXPECT_EQ(4, cbuf.len);
  KEXPECT_STREQ("bcd345678a", cbuf_data);


  KTEST_BEGIN("circbuf: write wrapping from last element of buffer C");
  kstrcpy(cbuf_data, "0123456789");
  cbuf.pos = 6;
  cbuf.len = 3;

  KEXPECT_EQ(4, circbuf_write(&cbuf, out_buf, 4));
  KEXPECT_EQ(6, cbuf.pos);
  KEXPECT_EQ(7, cbuf.len);
  KEXPECT_STREQ("bcd345678a", cbuf_data);


  // TODO read all of non-full buffer


  // TODO
  //  - wrapping: both hitting full buffer, and end of write data
  //  - read and write full size
  //    - pos at start
  //    - pos in middle (wrap)
  //  - only read up to nbytes (with and without wrapping)
  //  - start is last element
}

static void peek_consume_test(void) {
  KTEST_BEGIN("circbuf: peek");
  char cbuf_data[CBUF_SIZE + 1];
  kmemset(cbuf_data, ' ', CBUF_SIZE);
  cbuf_data[CBUF_SIZE] = '\0';

  circbuf_t cbuf;
  circbuf_init(&cbuf, cbuf_data, CBUF_SIZE);
  cbuf.pos = 5;
  KEXPECT_EQ(8, circbuf_write(&cbuf, "01234567", 8));
  KEXPECT_STREQ("567  01234", cbuf_data);

  char buf[10];
  kmemset(buf, 0, 10);
  KEXPECT_EQ(3, circbuf_peek(&cbuf, buf, 0, 3));
  KEXPECT_STREQ("012", buf);
  kmemset(buf, 0, 10);
  KEXPECT_EQ(5, circbuf_peek(&cbuf, buf, 0, 5));
  KEXPECT_STREQ("01234", buf);
  kmemset(buf, 0, 10);
  KEXPECT_EQ(5, circbuf_peek(&cbuf, buf, 3, 5));
  KEXPECT_STREQ("34567", buf);
  kmemset(buf, 0, 10);
  KEXPECT_EQ(8, circbuf_peek(&cbuf, buf, 0, 10));
  KEXPECT_STREQ("01234567", buf);
  KEXPECT_EQ(1, circbuf_write(&cbuf, "a", 1));
  KEXPECT_STREQ("567a 01234", cbuf_data);
  kmemset(buf, 0, 10);
  KEXPECT_EQ(9, circbuf_peek(&cbuf, buf, 0, 10));
  KEXPECT_STREQ("01234567a", buf);
  kmemset(buf, 0, 10);
  KEXPECT_EQ(6, circbuf_peek(&cbuf, buf, 3, 10));
  KEXPECT_STREQ("34567a", buf);
  kmemset(buf, 0, 10);
  KEXPECT_EQ(1, circbuf_peek(&cbuf, buf, 8, 10));
  KEXPECT_STREQ("a", buf);
  kmemset(buf, 0, 10);
  KEXPECT_EQ(2, circbuf_peek(&cbuf, buf, 7, 10));
  KEXPECT_STREQ("7a", buf);
  kmemset(buf, 0, 10);
  KEXPECT_EQ(0, circbuf_peek(&cbuf, buf, 9, 10));
  KEXPECT_STREQ("", buf);
  KEXPECT_EQ(0, circbuf_peek(&cbuf, buf, 10, 10));
  KEXPECT_STREQ("", buf);
  KEXPECT_EQ(0, circbuf_peek(&cbuf, buf, 15, 10));
  KEXPECT_STREQ("", buf);
  kmemset(buf, 0, 10);
  KEXPECT_EQ(9, circbuf_peek(&cbuf, buf, 0, 20));
  KEXPECT_STREQ("01234567a", buf);

  KTEST_BEGIN("circbuf: consume");
  KEXPECT_EQ(3, circbuf_consume(&cbuf, 3));
  kmemset(buf, 0, 10);
  KEXPECT_EQ(6, circbuf_peek(&cbuf, buf, 0, 10));
  KEXPECT_STREQ("34567a", buf);
  KEXPECT_EQ(4, circbuf_consume(&cbuf, 4));
  kmemset(buf, 0, 10);
  KEXPECT_EQ(2, circbuf_read(&cbuf, buf, 20));
  KEXPECT_STREQ("7a", buf);
  KEXPECT_EQ(0, circbuf_peek(&cbuf, buf, 0, 10));
  KEXPECT_EQ(0, cbuf.len);
}

void circbuf_test(void) {
  KTEST_SUITE_BEGIN("circbuf_t tests");
  basic_test();
  peek_consume_test();
}
