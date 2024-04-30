// Copyright 2024 Andrew Oates.  All Rights Reserved.
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

// A basic userspace implementation of select() that is implemented with poll().

#include <errno.h>
#include <poll.h>
#include <stdlib.h>
#include <sys/select.h>

int select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds,
           struct timeval *timeout) {
  if (nfds < 0 || nfds > FD_SETSIZE) {
    errno = EINVAL;
    return -1;
  }

  fd_set allfds;
  int allfds_count = 0;
  FD_ZERO(&allfds);
  for (int i = 0; i < nfds; ++i) {
    if ((readfds && FD_ISSET(i, readfds)) ||
        (writefds && FD_ISSET(i, writefds)) ||
        (exceptfds && FD_ISSET(i, exceptfds))) {
      FD_SET(i, &allfds);
      allfds_count++;
    }
  }

  struct pollfd *pfds =
      (struct pollfd *)malloc(sizeof(struct pollfd) * allfds_count);
  int allfds_idx = 0;
  for (int i = 0; i < nfds; ++i) {
    if (FD_ISSET(i, &allfds)) {
      struct pollfd* pfd = &pfds[allfds_idx];
      allfds_idx++;
      pfd->fd = i;
      pfd->events = 0;
      if (readfds && FD_ISSET(i, readfds)) {
        pfd->events |= POLLIN;
      }
      if (writefds && FD_ISSET(i, writefds)) {
        pfd->events |= POLLOUT;
      }
    }
  }
  long timeout_ms = (timeout == NULL)
                        ? -1
                        : (timeout->tv_sec * 1000 + timeout->tv_usec / 1000);

  // We need to AND the result with the input for exceptfds.
  fd_set exceptfds_out;
  FD_ZERO(&exceptfds_out);
  if (readfds) {
    FD_ZERO(readfds);
  }
  if (writefds) {
    FD_ZERO(writefds);
  }

  int result = poll(pfds, allfds_count, timeout_ms);
  if (result <= 0) {
    if (exceptfds) {
      FD_ZERO(exceptfds);
    }
    free(pfds);
    return result;
  }

  for (int i = 0; i < allfds_count; ++i) {
    if (pfds[i].revents & POLLNVAL) {
      free(pfds);
      errno = EBADF;
      return -1;
    }
    if (readfds && (pfds[i].revents & POLLIN)) {
      FD_SET(pfds[i].fd, readfds);
    }
    if (writefds && (pfds[i].revents & POLLOUT)) {
      FD_SET(pfds[i].fd, writefds);
    }
    if (exceptfds && FD_ISSET(pfds[i].fd, exceptfds) &&
        (pfds[i].revents & POLLERR)) {
      FD_SET(pfds[i].fd, &exceptfds_out);
    }
  }
  if (exceptfds) {
    FD_COPY(&exceptfds_out, exceptfds);
  }
  free(pfds);
  return result;
}
