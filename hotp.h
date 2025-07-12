#ifndef HOTP_H
#define HOTP_H

#include <stdint.h>

uint32_t hotp(const char *K, size_t KL, uint64_t C);

#endif // HOTP_H
