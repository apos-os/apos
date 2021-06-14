// Copyright 2021 Andrew Oates.  All Rights Reserved.
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

#include "os/common/passwd.h"

#include <assert.h>
#include <errno.h>
#include <pwd.h>
#include <stdio.h>
#include <string.h>

#define LONG_NAME                                                              \
  "nametoolong111111111111111111111111111111111111111111111111111111111111111" \
  "1111111111111111111111111111111111114"

#define SUPER_LONG_NAME                                                 \
  LONG_NAME LONG_NAME LONG_NAME LONG_NAME LONG_NAME LONG_NAME LONG_NAME \
      LONG_NAME LONG_NAME LONG_NAME LONG_NAME

static const char kTestPasswd[] =
    ":invalid:123:456:test stuff:/home/user:/bin/sh\n"  // Empty username.
    "invalid2:123:456:test stuff:/home/user:/bin/sh\n"  // Missing field.
    "negative1:abc:-123:456:test stuff:/home/user:/bin/sh\n"
    "negative2:abc:123:-456:test stuff:/home/user:/bin/sh\n"
    "toobig1:abc:123456789123456789:456:test stuff:/home/user:/bin/sh\n"
    "toobig2:abc:1:123456789123456789:test stuff:/home/user:/bin/sh\n"
    "toolong:abc:123:456:test stuff:/home/user:/bin/sh:xxx:yyy\n"  //
    LONG_NAME ":abc:123:456:test stuff:/home/user:/bin/sh:xxx:yyy\n"
    // This line is way too long; do two in a row.
    SUPER_LONG_NAME
    ":abc:123:456:test stuff:/home/user:/bin/sh:xxx:yyy\n"
    SUPER_LONG_NAME
    ":abc:123:456:test stuff:/home/user:/bin/sh:xxx:yyy\n"
    "user:abc:123:456:test stuff:/home/user:/bin/sh\n"
    // A singleton too-long line after/before a valid one.
    SUPER_LONG_NAME
    ":abc:123:456:test stuff:/home/user:/bin/sh:xxx:yyy\n"
    "username:def:4:6:???:/home/user2:/bin/zsh";

// TODO(aoates): do this with a proper unit test library.
static void passwd_test(void) {
  FILE* pfile = fmemopen((void*)kTestPasswd, strlen(kTestPasswd), "r");
  assert(pfile != NULL);

  const int kBufSize = 1024;
  char buf[kBufSize];
  struct passwd pwd;

  assert(-1 == apos_get_pwent_f(pfile, "a", &pwd, buf, kBufSize));
  assert(errno == ENOENT);
  assert(-1 == apos_get_pwent_f(pfile, "user2", &pwd, buf, kBufSize));
  assert(errno == ENOENT);
  assert(-1 == apos_get_pwent_f(pfile, "username:", &pwd, buf, kBufSize));
  assert(errno == ENOENT);
  assert(-1 == apos_get_pwent_f(pfile, "user:", &pwd, buf, kBufSize));
  assert(errno == ENOENT);
  assert(-1 == apos_get_pwent_f(pfile, "invalid", &pwd, buf, kBufSize));
  assert(errno == ENOENT);
  assert(-1 == apos_get_pwent_f(pfile, ":invalid", &pwd, buf, kBufSize));
  assert(errno == ENOENT);
  assert(-1 == apos_get_pwent_f(pfile, "invalid2", &pwd, buf, kBufSize));
  assert(errno == ENOENT);
  assert(-1 == apos_get_pwent_f(pfile, "invalid2:", &pwd, buf, kBufSize));
  assert(errno == ENOENT);

  assert(0 == apos_get_pwent_f(pfile, "negative1", &pwd, buf, kBufSize));
  assert((uid_t)-123 == pwd.pw_uid);
  assert(0 == apos_get_pwent_f(pfile, "negative2", &pwd, buf, kBufSize));
  assert((gid_t)-456 == pwd.pw_gid);
  assert(0 == apos_get_pwent_f(pfile, "toobig1", &pwd, buf, kBufSize));
  assert(pwd.pw_gid == 456);
  assert(0 == apos_get_pwent_f(pfile, "toobig2", &pwd, buf, kBufSize));
  assert(pwd.pw_uid == 1);

  assert(0 == apos_get_pwent_f(pfile, "user", &pwd, buf, kBufSize));
  assert(0 == strcmp(pwd.pw_name, "user"));
  assert(0 == strcmp(pwd.pw_passwd, "abc"));
  assert(pwd.pw_uid == 123);
  assert(pwd.pw_gid == 456);
  assert(0 == strcmp(pwd.pw_gecos, "test stuff"));
  assert(0 == strcmp(pwd.pw_dir , "/home/user"));
  assert(0 == strcmp(pwd.pw_shell, "/bin/sh"));

  assert(0 == apos_get_pwent_f(pfile, "username", &pwd, buf, kBufSize));
  assert(0 == strcmp(pwd.pw_name, "username"));
  assert(0 == strcmp(pwd.pw_passwd, "def"));
  assert(pwd.pw_uid == 4);
  assert(pwd.pw_gid == 6);
  assert(0 == strcmp(pwd.pw_gecos, "???"));
  assert(0 == strcmp(pwd.pw_dir , "/home/user2"));
  assert(0 == strcmp(pwd.pw_shell, "/bin/zsh"));

  assert(strlen(LONG_NAME) > 100);
  assert(-1 == apos_get_pwent_f(pfile, LONG_NAME, &pwd, buf, kBufSize));
  assert(errno == EINVAL);

  // Given (current) size of the internal buffer, this is the "leftover" amount
  // in the very long line.
  assert(-1 == apos_get_pwent_f(pfile, "1111111111114", &pwd, buf, kBufSize));
  assert(errno == ENOENT);

  // Test for too-small buffers.
  assert(-1 == apos_get_pwent_f(pfile, "user", &pwd, buf, 10));
  assert(errno == ENOMEM);
  assert(-1 == apos_get_pwent_f(pfile, "user", &pwd, buf, 50));
  assert(errno == ENOMEM);

  fclose(pfile);
}

static const char kTestShadow[] =
    ":$a$123$5552\n"  // Missing username.
    "invalid2\n"      // Missing password.
    "us:xy\n"
    "user1:abc\n"
    "user2:\n"
    "user3:def:xyz\n"
    "toolong:def:" SUPER_LONG_NAME "\n"
    "user4:$1$528$a53f3:5";

static void shadow_test(void) {
  FILE* pfile = fmemopen((void*)kTestShadow, strlen(kTestShadow), "r");
  assert(pfile != NULL);

  const int kBufSize = 1024;
  char buf[kBufSize];

  assert(-1 == apos_get_shpwent_f(pfile, "a", buf, kBufSize));
  assert(errno == ENOENT);
  assert(-1 == apos_get_shpwent_f(pfile, "user1:", buf, kBufSize));
  assert(errno == ENOENT);
  assert(-1 == apos_get_shpwent_f(pfile, "invalid2", buf, kBufSize));
  assert(errno == ENOENT);
  assert(-1 == apos_get_shpwent_f(pfile, "invalid2:", buf, kBufSize));
  assert(errno == ENOENT);

  assert(2 == apos_get_shpwent_f(pfile, "us", buf, kBufSize));
  assert(0 == strcmp(buf, "xy"));
  assert(3 == apos_get_shpwent_f(pfile, "user1", buf, kBufSize));
  assert(0 == strcmp(buf, "abc"));
  assert(2 == apos_get_shpwent_f(pfile, "user1", buf, 3));
  assert(0 == strcmp(buf, "ab"));
  assert(1 == apos_get_shpwent_f(pfile, "user1", buf, 2));
  assert(0 == strcmp(buf, "a"));
  assert(0 == apos_get_shpwent_f(pfile, "user1", buf, 1));
  assert(0 == strcmp(buf, ""));
  assert(0 == apos_get_shpwent_f(pfile, "user2", buf, kBufSize));
  assert(0 == strcmp(buf, ""));
  assert(3 == apos_get_shpwent_f(pfile, "user3", buf, kBufSize));
  assert(0 == strcmp(buf, "def"));
  assert(12 == apos_get_shpwent_f(pfile, "user4", buf, kBufSize));
  assert(0 == strcmp(buf, "$1$528$a53f3"));
  assert(-1 == apos_get_shpwent_f(pfile, "user", buf, kBufSize));
  assert(errno == ENOENT);
  assert(-1 == apos_get_shpwent_f(pfile, "toolong", buf, kBufSize));
  assert(errno == ENOENT);

  assert(-1 == apos_get_shpwent_f(pfile, LONG_NAME, buf, kBufSize));
  assert(errno == EINVAL);

  fclose(pfile);
}

int main(int argc, char** argv) {
  passwd_test();
  shadow_test();
  printf("PASSED\n");
  return 0;
}
