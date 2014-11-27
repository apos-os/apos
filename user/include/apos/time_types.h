#ifndef APOO_USER_INCLUDE_APOS_TIME_TYPES_H
#define APOO_USER_INCLUDE_APOS_TIME_TYPES_H

#include <sys/types.h>

struct timespec {
  time_t  tv_sec;
  long    tv_nsec;
};

#endif
