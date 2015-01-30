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

// List of syscalls.  Generated from user/syscalls.h.tpl.
#ifndef APOO_USER_SYSCALLS_H
#define APOO_USER_SYSCALLS_H

// All syscalls and their numbers.
#define SYS_SYSCALL_TEST 0
#define SYS_OPEN 1
#define SYS_CLOSE 2
#define SYS_DUP 45
#define SYS_DUP2 46
#define SYS_MKDIR 3
#define SYS_MKNOD 4
#define SYS_RMDIR 5
#define SYS_UNLINK 6
#define SYS_READ 7
#define SYS_WRITE 8
#define SYS_GETDENTS 10
#define SYS_GETCWD 11
#define SYS_STAT 35
#define SYS_LSTAT 36
#define SYS_FSTAT 37
#define SYS_LSEEK 38
#define SYS_CHDIR 12
#define SYS_ACCESS 47
#define SYS_CHOWN 48
#define SYS_FCHOWN 49
#define SYS_LCHOWN 50
#define SYS_FORK 13
#define SYS_EXIT 14
#define SYS_WAIT 41
#define SYS_WAITPID 62
#define SYS_EXECVE 15
#define SYS_GETPID 16
#define SYS_GETPPID 17
#define SYS_ISATTY 18
#define SYS_KILL 19
#define SYS_SIGACTION 20
#define SYS_SIGPROCMASK 52
#define SYS_SIGPENDING 53
#define SYS_SIGSUSPEND 61
#define SYS_SIGRETURN 21
#define SYS_ALARM_MS 22
#define SYS_SETUID 23
#define SYS_SETGID 24
#define SYS_GETUID 25
#define SYS_GETGID 26
#define SYS_SETEUID 27
#define SYS_SETEGID 28
#define SYS_GETEUID 29
#define SYS_GETEGID 30
#define SYS_SETREUID 31
#define SYS_SETREGID 32
#define SYS_GETPGID 33
#define SYS_SETPGID 34
#define SYS_MMAP 39
#define SYS_MUNMAP 40
#define SYS_SYMLINK 42
#define SYS_READLINK 43
#define SYS_SLEEP_MS 44
#define SYS_APOS_GET_TIME 51
#define SYS_PIPE 54
#define SYS_UMASK 55
#define SYS_SETSID 56
#define SYS_GETSID 57
#define SYS_TCGETPGRP 58
#define SYS_TCSETPGRP 59
#define SYS_TCGETSID 60
#define SYS_TCDRAIN 63
#define SYS_TCFLUSH 64
#define SYS_TCGETATTR 65
#define SYS_TCSETATTR 66

#endif
