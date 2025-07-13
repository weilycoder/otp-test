#ifndef HOTP_H
#define HOTP_H

#include <stddef.h>
#include <stdint.h>

#define MEM_ALLOC_FAILED 0x80000000U
#define BASE32_DECODE_FAILED 0x80000001U
#define HMAC_FAILED 0x80000002U

uint32_t otp(const char *K, uint64_t C);

#endif // HOTP_H
