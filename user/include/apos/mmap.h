#ifndef APOO_USER_MMAP_H
#define APOO_USER_MMAP_H

// Memory protection flags.
#define PROT_NONE 0x00
#define PROT_READ 0x01
#define PROT_WRITE 0x02
#define PROT_EXEC 0x04

// Exactly one of MAP_SHARED and MAP_PRIVATE must be given.
#define MAP_SHARED 0x01
#define MAP_PRIVATE 0x02

// Other flags.
#define MAP_FIXED 0x04
#define MAP_ANONYMOUS 0x08

#endif
