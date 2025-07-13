#include "otp.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "base32.h"
#include "hmac.h"
#include "sha1.h"

static char *hmac_sha1(const char *K, size_t Klen, const char *text, size_t text_len, char *digest) {
  return hmac(K, Klen, text, text_len, sha1, SHA1_BLOCK_SIZE, SHA1_DIGEST_SIZE, digest);
}

static uint32_t truncate(const char *hmac_sha1_result) {
  size_t offset = hmac_sha1_result[SHA1_DIGEST_SIZE - 1] & 0x0F;
  uint32_t value = ((uint32_t)(uint8_t)hmac_sha1_result[offset] << 24) |
                   ((uint32_t)(uint8_t)hmac_sha1_result[offset + 1] << 16) |
                   ((uint32_t)(uint8_t)hmac_sha1_result[offset + 2] << 8) |
                   ((uint32_t)(uint8_t)hmac_sha1_result[offset + 3]);
  return value & 0x7FFFFFFF;
}

static uint32_t _otp(const char *K, size_t KL, uint64_t C) {
  char hmac_result[SHA1_DIGEST_SIZE];
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
  C = __builtin_bswap64(C);
#endif
  char *counter = (char *)&C;
  if (hmac_sha1(K, KL, counter, sizeof(C), hmac_result) == NULL)
    return HMAC_FAILED;
  return truncate(hmac_result);
}

uint32_t otp(const char *K, uint64_t C) {
  size_t KL = strlen(K);
  size_t key_size = decode_size(K);
  char *decoded_key = (char *)malloc(key_size + 1);
  if (decoded_key == NULL)
    return MEM_ALLOC_FAILED;
  if (b32decode(K, KL, decoded_key) == NULL) {
    free(decoded_key);
    return BASE32_DECODE_FAILED;
  }
  uint32_t result = _otp(decoded_key, key_size, C);
  free(decoded_key);
  return result;
}
