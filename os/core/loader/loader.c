// Copyright 2025 Andrew Oates.  All Rights Reserved.
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

#include "os/core/loader/ld_printf.h"
#include "os/core/loader/syscalls.h"

int main(int argc, char *argv[], char *envp[]) {
  int val = 0;
  ld_printf("Running loader.\n");
  ld_printf("  Args (argc = %d):\n", argc);
  for (int i = 0; i < argc; ++i) {
    ld_printf("    argv[%d] = '%s'\n", i, argv[i]);
  }
  ld_printf("  Current stack ptr is %p\n", &val);
  ld_printf("  Address of main() is %p\n", &main);
  ld_printf("  __builtin_return_address(0): %p\n", __builtin_return_address(0));
  ld_exit(0);
}

void _start(char** argv, char** envp) {
  // TODO(aoates): figure out if we need to set up gp on riscv here.
  int argc = 0;
  while (argv[argc] != 0x0) argc++;
  int exit_code = main(argc, argv, envp);
  ld_exit(exit_code);
}
