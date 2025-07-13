#ifndef HOTP_H
#define HOTP_H

#include <stddef.h>
#include <stdint.h>

extern const uint32_t MEM_ALLOC_FAILED;
extern const uint32_t BASE32_DECODE_FAILED;
uint32_t hotp(const char *K, uint64_t C);

#endif // HOTP_H
