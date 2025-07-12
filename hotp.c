// Only for little-endian systems.

#include "hmac.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "hmac.h"
#include "sha1.h"

static char *hmac_sha1(const char *K, size_t Klen, const char *text, size_t text_len, char *digest) {
  return hmac(K, Klen, text, text_len, sha1, SHA1_BLOCK_SIZE, SHA1_DIGEST_SIZE, digest);
}

static uint32_t truncate(const char *hmac_sha1_result) {
  size_t offset = hmac_sha1_result[SHA1_DIGEST_SIZE - 1] & 0x0F;
  return __builtin_bswap32(*(uint32_t *)(hmac_sha1_result + offset)) & 0x7fffffff;
}

uint32_t hotp(const char *K, size_t KL, uint64_t C) {
  char hmac_result[SHA1_DIGEST_SIZE];
  C = __builtin_bswap64(C); // Convert counter to big-endian
  char *counter = (char *)&C;
  hmac_sha1(K, KL, counter, sizeof(C), hmac_result);
  return truncate(hmac_result);
}
