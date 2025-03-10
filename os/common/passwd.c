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
#include <stdbool.h>
#include <string.h>

#define MAX_PASSWDFIELD_LEN 100
#define PASSWDBUF_MIN_SIZE ((MAX_PASSWDFIELD_LEN + 1) * 5)

#define MIN(a, b)           \
  ({                        \
    __typeof__(a) _a = (a); \
    __typeof__(b) _b = (b); \
    _a < _b ? _a : _b;      \
  })

static const char kPasswdFile[] = "/etc/passwd";
static const char kShadowFile[] = "/etc/shadow";

// Gets the next line from the FILE, skipping lines that are too long.
static char* fgets_capped(char* buf, size_t bufsize, FILE* file) {
  bool too_long = false;
  while (true) {
    if (!fgets(buf, bufsize, file)) {
      return NULL;
    }
    const size_t linelen = strlen(buf);
    assert(linelen > 0);
    if (buf[linelen - 1] == '\n' || feof(file)) {
      if (too_long) {
        // Hit end of the too-long line; reset and continue.
        too_long = false;
        continue;
      } else {
        return buf;  // Normal line.
      }
    }
    if (!too_long) {
      fprintf(stderr, "Warning: ignoring too-long line in passwd file\n");
      too_long = true;
    }
  }
}

// TODO(aoates): upstream this into libc.
int apos_get_pwent(const char* user, struct passwd* pwd, char* buf,
                   size_t bufsize) {
  FILE* pfile = fopen(kPasswdFile, "r");
  if (!pfile) {
    return -1;
  }

  int result = apos_get_pwent_f(pfile, user, pwd, buf, bufsize);
  fclose(pfile);
  return result;
}

int apos_get_pwent_f(FILE* passwd_file, const char* user, struct passwd* pwd,
                     char* buf, size_t bufsize) {
  if (bufsize < PASSWDBUF_MIN_SIZE) {
    errno = ENOMEM;
    return -1;
  }
  const size_t user_len = strlen(user);
  if (user_len > MAX_PASSWDFIELD_LEN) {
    errno = EINVAL;
    return -1;
  }
  if (fseek(passwd_file, 0, SEEK_SET) != 0) {
    return -1;
  }

  pwd->pw_name = buf;
  pwd->pw_passwd = &buf[MAX_PASSWDFIELD_LEN + 1];
  pwd->pw_gecos = &buf[2 * (MAX_PASSWDFIELD_LEN + 1)];
  pwd->pw_dir = &buf[3 * (MAX_PASSWDFIELD_LEN + 1)];
  pwd->pw_shell = &buf[4 * (MAX_PASSWDFIELD_LEN + 1)];

  // If changed, update the too-long-line test.
  const int kBufSize = PASSWDBUF_MIN_SIZE + 100;
  char linebuf[kBufSize];
  int line_idx = -1;
  while (fgets_capped(linebuf, kBufSize, passwd_file)) {
    line_idx++;
    if (strncmp(linebuf, user, user_len) != 0 || linebuf[user_len] != ':') {
      continue;
    }
    int result =
        sscanf(linebuf, "%99[^:]:%99[^:]:%u:%u:%99[^:]:%99[^:]:%99[^:\n]",
               pwd->pw_name, pwd->pw_passwd, &pwd->pw_uid, &pwd->pw_gid,
               pwd->pw_gecos, pwd->pw_dir, pwd->pw_shell);
    if (result != 7) {
      fprintf(
          stderr,
          "Warning: malformed passwd file (line %d; only parsed %d fields)\n",
          line_idx, result);
      continue;
    }
    return 0;
  }

  if (ferror(passwd_file)) {
    return -1;
  }

  errno = ENOENT;
  return -1;
}

int apos_get_shpwent(const char* user, char* buf, size_t bufsize) {
  FILE* pfile = fopen(kShadowFile, "r");
  if (!pfile) {
    return -1;
  }

  int result = apos_get_shpwent_f(pfile, user, buf, bufsize);
  fclose(pfile);
  return result;
}

int apos_get_shpwent_f(FILE* passwd_file, const char* user, char* buf,
                       size_t bufsize) {
  const size_t user_len = strlen(user);
  if (user_len > MAX_PASSWDFIELD_LEN) {
    errno = EINVAL;
    return -1;
  }
  if (fseek(passwd_file, 0, SEEK_SET) != 0) {
    return -1;
  }

  // If changed, update the too-long-line test.
  const int kBufSize = 2 * MAX_PASSWDFIELD_LEN + 10;
  char linebuf[kBufSize];
  while (fgets_capped(linebuf, kBufSize, passwd_file)) {
    if (strncmp(linebuf, user, user_len) != 0 || linebuf[user_len] != ':') {
      continue;
    }
    char* pw_start = linebuf + user_len + 1;
    char* pw_end = pw_start;
    strsep(&pw_end, ":\n");
    const size_t len = MIN(bufsize - 1, strlen(pw_start));
    strncpy(buf, pw_start, len);
    buf[len] = '\0';
    return len;
  }

  if (ferror(passwd_file)) {
    return -1;
  }

  errno = ENOENT;
  return -1;
}
