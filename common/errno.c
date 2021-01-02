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

const char* errorname(int err) {
#define HANDLE(ERR)                                    \
  _Static_assert(ERR >= ERRNO_MIN && ERR <= ERRNO_MAX, \
                 "Error " #ERR " out of bounds");      \
  case ERR:                                            \
    return #ERR;

  switch(err) {
    case 0: return "OK";

    HANDLE(E2BIG);
    HANDLE(EACCES);
    HANDLE(EADDRINUSE);
    HANDLE(EADDRNOTAVAIL);
    HANDLE(EAFNOSUPPORT);
    HANDLE(EAGAIN);
    HANDLE(EALREADY);
    HANDLE(EBADF);
    HANDLE(EBADMSG);
    HANDLE(EBUSY);
    HANDLE(ECANCELED);
    HANDLE(ECHILD);
    HANDLE(ECONNABORTED);
    HANDLE(ECONNREFUSED);
    HANDLE(ECONNRESET);
    HANDLE(EDEADLK);
    HANDLE(EDESTADDRREQ);
    HANDLE(EDOM);
    HANDLE(EDQUOT);
    HANDLE(EEXIST);
    HANDLE(EFAULT);
    HANDLE(EFBIG);
    HANDLE(EHOSTUNREACH);
    HANDLE(EIDRM);
    HANDLE(EILSEQ);
    HANDLE(EINPROGRESS);
    HANDLE(EINTR);
    HANDLE(EINVAL);
    HANDLE(EIO);
    HANDLE(EISCONN);
    HANDLE(EISDIR);
    HANDLE(ELOOP);
    HANDLE(EMFILE);
    HANDLE(EMLINK);
    HANDLE(EMSGSIZE);
    HANDLE(EMULTIHOP);
    HANDLE(ENAMETOOLONG);
    HANDLE(ENETDOWN);
    HANDLE(ENETRESET);
    HANDLE(ENETUNREACH);
    HANDLE(ENFILE);
    HANDLE(ENOBUFS);
    HANDLE(ENODEV);
    HANDLE(ENOENT);
    HANDLE(ENOEXEC);
    HANDLE(ENOLCK);
    HANDLE(ENOLINK);
    HANDLE(ENOMEM);
    HANDLE(ENOMSG);
    HANDLE(ENOPROTOOPT);
    HANDLE(ENOSPC);
    HANDLE(ENOSYS);
    HANDLE(ENOTCONN);
    HANDLE(ENOTDIR);
    HANDLE(ENOTEMPTY);
    HANDLE(ENOTSOCK);
    HANDLE(ENOTSUP);
    HANDLE(ENOTTY);
    HANDLE(ENXIO);
    HANDLE(EOPNOTSUPP);
    HANDLE(EOVERFLOW);
    HANDLE(EPERM);
    HANDLE(EPIPE);
    HANDLE(EPROTO);
    HANDLE(EPROTONOSUPPORT);
    HANDLE(EPROTOTYPE);
    HANDLE(ERANGE);
    HANDLE(EROFS);
    HANDLE(ESPIPE);
    HANDLE(ESRCH);
    HANDLE(ESTALE);
    HANDLE(ETIMEDOUT);
    HANDLE(ETXTBSY);
#if EWOULDBLOCK != EAGAIN
    HANDLE(EWOULDBLOCK);
#endif
    HANDLE(EXDEV);
    HANDLE(EINTR_RESTART);
    HANDLE(EINJECTEDFAULT);
    HANDLE(ERENAMESAMEVNODE);
#if ERRNO_MAX != 77
#error Need to update errorname()
#endif

    default:
      return "<invalid error code>";
  }
# undef HANDLE
}
