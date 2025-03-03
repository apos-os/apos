// Copyright 2020 Andrew Oates.  All Rights Reserved.
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

// Defines constants related to signal handling.  Do not include directly.
#ifndef APOO_USER_INCLUDE_APOS__POSIX_SIGNAL_CONSTANTS_H
#define APOO_USER_INCLUDE_APOS__POSIX_SIGNAL_CONSTANTS_H

// Signal numbers.
#define SIGABRT   1   // Process abort signal.
#define SIGALRM   2   // Alarm clock.
#define SIGBUS    3   // Access to an undefined portion of a memory object.
#define SIGCHLD   4   // Child process terminated, stopped, or continued.
#define SIGCONT   5   // Continue executing, if stopped.
#define SIGFPE    6   // Erroneous arithmetic operation.
#define SIGHUP    7   // Hangup.
#define SIGILL    8   // Illegal instruction.
#define SIGINT    9   // Terminal interrupt signal.
#define SIGKILL   10  // Kill (cannot be caught or ignored).
#define SIGPIPE   11  // Write on a pipe with no one to read it.
#define SIGQUIT   12  // Terminal quit signal.
#define SIGSEGV   13  // Invalid memory reference.
#define SIGSTOP   14  // Stop executing (cannot be caught or ignored).
#define SIGTERM   15  // Termination signal.
#define SIGTSTP   16  // Terminal stop signal.
#define SIGTTIN   17  // Background process attempting read.
#define SIGTTOU   18  // Background process attempting write.
#define SIGUSR1   19  // User-defined signal 1.
#define SIGUSR2   20  // User-defined signal 2.
#define SIGSYS    21  // Bad system call.
#define SIGTRAP   22  // Trace/breakpoint trap.
#define SIGURG    23  // High bandwidth data is available at a socket.
#define SIGVTALRM 24  // Virtual timer expired.
#define SIGXCPU   25  // CPU time limit exceeded.
#define SIGXFSZ   26  // File size limit exceeded.

// The following signals are not specified in POSIX.
#define SIGWINCH  27  // Controlling terminal changed size.

// Signals that are used internally within the kernel.
#if __APOS_BUILDING_KERNEL__
#define SIGAPOSTEST 28  // Internal: test signal.
#define SIGAPOSTKILL 29  // Internal: kill a thread.
#define SIGAPOS_FORCE_CONT 30  // Internal: continue the process.
#endif

#define APOS_SIGNULL 0
#define APOS_SIGMIN 1
#define APOS_SIGMAX 30

// sighandler_t constants.
#define SIG_DFL ((ksighandler_t)0x0)
#define SIG_IGN ((ksighandler_t)0x1)

// sa_flags flags.
#define SA_RESTART 1
#define SA_NODEFER 2

// Actions for sigprocmask().
#define SIG_BLOCK 1
#define SIG_UNBLOCK 2
#define SIG_SETMASK 3

#endif
