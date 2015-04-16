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

#include "common/errno.h"

static const char* ERROR_STRINGS[ERRNO_MAX + 1] = {
  "OK",              // 0
  "E2BIG",           // 1
  "EACCES",          // 2
  "EADDRINUSE",      // 3
  "EADDRNOTAVAIL",   // 4
  "EAFNOSUPPORT",    // 5
  "EAGAIN",          // 6
  "EALREADY",        // 7
  "EBADF",           // 8
  "EBADMSG",         // 9
  "EBUSY",           // 10
  "ECANCELED",       // 11
  "ECHILD",          // 12
  "ECONNABORTED",    // 13
  "ECONNREFUSED",    // 14
  "ECONNRESET",      // 15
  "EDEADLK",         // 16
  "EDESTADDRREQ",    // 17
  "EDOM",            // 18
  "EDQUOT",          // 19
  "EEXIST",          // 20
  "EFAULT",          // 21
  "EFBIG",           // 22
  "EHOSTUNREACH",    // 23
  "EIDRM",           // 24
  "EILSEQ",          // 25
  "EINPROGRESS",     // 26
  "EINTR",           // 27
  "EINVAL",          // 28
  "EIO",             // 29
  "EISCONN",         // 30
  "EISDIR",          // 31
  "ELOOP",           // 32
  "EMFILE",          // 33
  "EMLINK",          // 34
  "EMSGSIZE",        // 35
  "EMULTIHOP",       // 36
  "ENAMETOOLONG",    // 37
  "ENETDOWN",        // 38
  "ENETRESET",       // 39
  "ENETUNREACH",     // 40
  "ENFILE",          // 41
  "ENOBUFS",         // 42
  "ENODEV",          // 43
  "ENOENT",          // 44
  "ENOEXEC",         // 45
  "ENOLCK",          // 46
  "ENOLINK",         // 47
  "ENOMEM",          // 48
  "ENOMSG",          // 49
  "ENOPROTOOPT",     // 50
  "ENOSPC",          // 51
  "ENOSYS",          // 52
  "ENOTCONN",        // 53
  "ENOTDIR",         // 54
  "ENOTEMPTY",       // 55
  "ENOTSOCK",        // 56
  "ENOTSUP",         // 57
  "ENOTTY",          // 58
  "ENXIO",           // 59
  "EOPNOTSUPP",      // 60
  "EOVERFLOW",       // 61
  "EPERM",           // 62
  "EPIPE",           // 63
  "EPROTO",          // 64
  "EPROTONOSUPPORT", // 65
  "EPROTOTYPE",      // 66
  "ERANGE",          // 67
  "EROFS",           // 68
  "ESPIPE",          // 69
  "ESRCH",           // 70
  "ESTALE",          // 71
  "ETIMEDOUT",       // 72
  "ETXTBSY",         // 73
//  "EWOULDBLOCK",     // 6
  "EXDEV",           // 74
  "EINTR_RESTART",   // 75
};

const char* errorname(int err) {
  if (err >= 0 && err <= ERRNO_MAX) {
    return ERROR_STRINGS[err];
  } else {
    return "<invalid error code>";
  }
}
