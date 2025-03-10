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

// Error codes.  Derived from the POSIX spec.
#ifndef APOO_USER_ERRORS_H
#define APOO_USER_ERRORS_H

#define ERRNO_MIN        1
#define E2BIG            1   // Argument list too long.
#define EACCES           2   // Permission denied.
#define EADDRINUSE       3   // Address in use.
#define EADDRNOTAVAIL    4   // Address not available.
#define EAFNOSUPPORT     5   // Address family not supported.
#define EAGAIN           6   // Resource unavailable, try again (may be the same value as [EWOULDBLOCK]).
#define EALREADY         7   // Connection already in progress.
#define EBADF            8   // Bad file descriptor.
#define EBADMSG          9   // Bad message.
#define EBUSY            10  // Device or resource busy.
#define ECANCELED        11  // Operation canceled.
#define ECHILD           12  // No child processes.
#define ECONNABORTED     13  // Connection aborted.
#define ECONNREFUSED     14  // Connection refused.
#define ECONNRESET       15  // Connection reset.
#define EDEADLK          16  // Resource deadlock would occur.
#define EDESTADDRREQ     17  // Destination address required.
#define EDOM             18  // Mathematics argument out of domain of function.
#define EDQUOT           19  // Reserved.
#define EEXIST           20  // File exists.
#define EFAULT           21  // Bad address.
#define EFBIG            22  // File too large.
#define EHOSTUNREACH     23  // Host is unreachable.
#define EIDRM            24  // Identifier removed.
#define EILSEQ           25  // Illegal byte sequence.
#define EINPROGRESS      26  // Operation in progress.
#define EINTR            27  // Interrupted function.
#define EINVAL           28  // Invalid argument.
#define EIO              29  // I/O error.
#define EISCONN          30  // Socket is connected.
#define EISDIR           31  // Is a directory.
#define ELOOP            32  // Too many levels of symbolic links.
#define EMFILE           33  // Too many open files.
#define EMLINK           34  // Too many links.
#define EMSGSIZE         35  // Message too large.
#define EMULTIHOP        36  // Reserved.
#define ENAMETOOLONG     37  // Filename too long.
#define ENETDOWN         38  // Network is down.
#define ENETRESET        39  // Connection aborted by network.
#define ENETUNREACH      40  // Network unreachable.
#define ENFILE           41  // Too many files open in system.
#define ENOBUFS          42  // No buffer space available.
#define ENODEV           43  // No such device.
#define ENOENT           44  // No such file or directory.
#define ENOEXEC          45  // Executable file format error.
#define ENOLCK           46  // No locks available.
#define ENOLINK          47  // Reserved.
#define ENOMEM           48  // Not enough space.
#define ENOMSG           49  // No message of the desired type.
#define ENOPROTOOPT      50  // Protocol not available.
#define ENOSPC           51  // No space left on device.
#define ENOSYS           52  // Function not supported.
#define ENOTCONN         53  // The socket is not connected.
#define ENOTDIR          54  // Not a directory.
#define ENOTEMPTY        55  // Directory not empty.
#define ENOTSOCK         56  // Not a socket.
#define ENOTSUP          57  // Not supported.
#define ENOTTY           58  // Inappropriate I/O control operation.
#define ENXIO            59  // No such device or address.
#define EOPNOTSUPP       60  // Operation not supported on socket.
#define EOVERFLOW        61  // Value too large to be stored in data type.
#define EPERM            62  // Operation not permitted.
#define EPIPE            63  // Broken pipe.
#define EPROTO           64  // Protocol error.
#define EPROTONOSUPPORT  65  // Protocol not supported.
#define EPROTOTYPE       66  // Protocol wrong type for socket.
#define ERANGE           67  // Result too large.
#define EROFS            68  // Read-only file system.
#define ESPIPE           69  // Invalid seek.
#define ESRCH            70  // No such process.
#define ESTALE           71  // Reserved.
#define ETIMEDOUT        72  // Connection timed out.
#define ETXTBSY          73  // Text file busy.
#define EWOULDBLOCK       6  // Operation would block (may be the same value as [EAGAIN]).
#define EXDEV            74  // Cross-device link.

// Internal errors.
#define EINTR_RESTART    75  // Interrupted syscall should be restarted.
#define EINJECTEDFAULT   76  // An artificially-injected error for tests.
#define ERENAMESAMEVNODE 77  // rename(A, B) resolved A and B to the same vnode.
#define ERRNO_MAX        77

#endif
