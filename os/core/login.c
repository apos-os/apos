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

#include <pwd.h>
#include <stdio.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

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

  // Restore terminal attributes.
  if (tcsetattr(0, TCSANOW, &orig_termios) < 0) {
    perror("Unable to restore tty with tcsetattr()\n");
    return 1;
  }

  printf("Logging in as %s (%s)\n", username, password);
  return 0;
}
