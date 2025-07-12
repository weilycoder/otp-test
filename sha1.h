#ifndef SHA1_H
#define SHA1_H

#include <stddef.h>
#include <stdint.h>

#define SHA1_BLOCK_SIZE 64  // SHA-1 processes data in 512-bit blocks (64 bytes)
#define SHA1_DIGEST_SIZE 20 // SHA-1 produces a 160-bit hash (20 bytes)

char *sha1(const char *data, size_t len, char *buf);

#endif // SHA1_H
