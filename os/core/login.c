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

#include <errno.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

#include "os/common/md5.h"
#include "os/common/passwd.h"

static void calculate_md5(char* md5_hex_out, const char* salt,
                          const char* password) {
  uint8_t md5[16];
  char* salted = NULL;
  asprintf(&salted, "%s!%s!%s", salt, password, salt);
  md5_hash(salted, strlen(salted), md5);
  free(salted);

  for (int i=  0; i < 16; ++i) {
    sprintf(md5_hex_out + 2 * i, "%02hhx", md5[i]);
  }
}

static int check_login(const char* username, const char* password,
                       struct passwd* pw, char* buf, size_t bufsize) {
  if (apos_get_pwent(username, pw, buf, bufsize)) {
    if (errno != ENOENT) {
      perror("Unable to read /etc/passwd");
    }
    fprintf(stderr, "Unknown user '%s'\n", username);
    return -1;
  }

  if (strcmp(pw->pw_passwd, "x") != 0) {
    fprintf(stderr, "User '%s' has unsupported non-shadow password\n",
            username);
    return -1;
  }

  char passwd_buf[100];
  if (apos_get_shpwent(username, passwd_buf, 100) < 0) {
    if (errno != ENOENT) {
      perror("Unable to read /etc/shadow");
    }
    fprintf(stderr, "User '%s' missing password\n", username);
    return -1;
  }

  char id[6], salt[51], hash[51];
  if (sscanf(passwd_buf, "$%5[^$]$%50[^$]$%50[^$]", id, salt, hash) != 3) {
    fprintf(stderr, "User '%s' has malformed password entry\n", username);
    return -1;
  }

  if (strcmp(id, "1") != 0) {
    fprintf(stderr, "User '%s' has unsupported password type\n", username);
    return -1;
  }

  char md5_str[40];
  calculate_md5(md5_str, salt, password);
  if (strcmp(md5_str, hash) != 0) {
    fprintf(stderr, "Incorrect password\n");
    return -1;
  }

  return 0;
}

int main(int argc, char** argv) {
  char username[100], password[100];

  // TODO(aoates): use /dev/tty for this when that exists.
  if (!isatty(0)) {
    fprintf(stderr, "error: login invoked on a non-TTY\n");
    return 1;
  }

  printf("login: ");
  scanf("%99s", username);

  // Disable echoing to get the password.
  // TODO(aoates): ideally would restore termios on SIGINT, etc.
  struct termios orig_termios, new_termios;
  if (tcgetattr(0, &orig_termios) < 0) {
    perror("Unable to tcgetattr() on stdin\n");
    return 1;
  }
  new_termios = orig_termios;
  new_termios.c_lflag &= ~(ECHO | ECHOE | ECHOK);
  if (tcsetattr(0, TCSANOW, &new_termios) < 0) {
    perror("Unable to disable echo with tcsetattr() on stdin\n");
    return 1;
  }
  printf("password: ");
  scanf("%99s", password);
  printf("\n");

  // Restore terminal attributes.
  if (tcsetattr(0, TCSANOW, &orig_termios) < 0) {
    perror("Unable to restore tty with tcsetattr()\n");
    return 1;
  }

  // Check login information.
  struct passwd pw;
  char buf[1000];
  if (check_login(username, password, &pw, buf, 1000)) {
    fprintf(stderr, "Unable to log in\n");
    exit(1);
  }

  // Switch to requested user.
  if (setregid(pw.pw_gid, pw.pw_gid) < 0) {
    perror("Unable to setregid");
    fprintf(stderr, "Unable to set gid to %d\n", pw.pw_gid);
    exit(1);
  }
  if (setreuid(pw.pw_uid, pw.pw_uid) < 0) {
    perror("Unable to setreuid");
    fprintf(stderr, "Unable to set uid to %d\n", pw.pw_uid);
    exit(1);
  }

  // Go to their homedir and execute their shell.
  if (chdir(pw.pw_dir) < 0) {
    perror("Unable to chdir to requested home directory");
    fprintf(stderr, "Unable to chdir to %s\n", pw.pw_dir);
    // ...but keep going.
  }

  // TODO(aoates): what environment variables should we set?
  char* shell_arg = NULL;
  asprintf(&shell_arg, "-%s", pw.pw_shell);
  char* shell_argv[] = {pw.pw_shell, shell_arg, NULL};
  char* shell_envp[] = {NULL};
  execve(pw.pw_shell, shell_argv, shell_envp);
  perror("Unable to exec user shell");
  fprintf(stderr, "Unable to exec user's shell '%s'\n", pw.pw_shell);
  return 1;
}
