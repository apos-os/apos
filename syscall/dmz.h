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

// The syscall DMZ is responsible for verifying validity of syscall arguments
// and copying buffers into kernel space (and back into user-space).  This
// ensures that user-mode code cannot use syscalls to access kernel memory or
// memory for other processes.  It also protects kernel code from blocking page
// faults --- any non-paged-in memory accesses will happen in the DMZ, when the
// buffers are being copied into kernel memory.
//
// This file contains DMZ utility functions for checking the validity of
// arguments.  Each syscall has an autogenerated DMZ function that calls these
// functions, does the appropriate copying, and invokes the real syscall.
#ifndef APOO_SYSCALL_DMZ_H
#define APOO_SYSCALL_DMZ_H

#include <stddef.h>

// Verify that the given buffer is allowed for a syscall (that is, that its
// entire length is within memory accessible to the current process).
//
// Returns 0 if the access is valid, -error if not.
int syscall_verify_buffer(const void* buf, size_t len, int is_write);

// Verify that the given NULL-terminated string is allowed for a syscall (that
// its entire length is within memory accessible to the current process).
//
// Returns the string's length (*including* the NULL) on success, or -error on
// error (-EFAULT if the string spans valid user memory).
//
// IMPORTANT NOTE: the caller MUST use the length returned by this function when
// accessing the string, as the memory may be concurrently modified by user
// code.
//
// That is, callers should use this function to determine the length and
// validity of the string, then treat it simply as a buffer of that size
// thereafter.
//
// Strings are assumed to be read-only.
int syscall_verify_string(const char* str);

// Verify a NULL-terminated pointer array of the form 'void* array[]'.
//
// Returns the length of the table (in pointer entries, not bytes), INCLUDING
// the terminating NULL on success, or -errno on error.
int syscall_verify_ptr_table(void* table[]);

#endif
