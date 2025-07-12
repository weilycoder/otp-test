#ifndef HMAC_H
#define HMAC_H

#include <stdint.h>

typedef char *(*HashFunction)(const char *data, size_t len, char *output);

char *hmac(const char *K, size_t KL, const char *D, size_t DL, HashFunction H, size_t B, size_t L, char *output);

#endif
