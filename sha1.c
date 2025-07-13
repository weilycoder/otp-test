#include "sha1.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define S(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

#define F1(b, c, d) (((b) & (c)) | ((~b) & (d)))
#define F2(b, c, d) ((b) ^ (c) ^ (d))
#define F3(b, c, d) (((b) & (c)) | ((b) & (d)) | ((c) & (d)))
#define F4(b, c, d) ((b) ^ (c) ^ (d))

static const char *update_sha1(const uint32_t input[16]) {
  static uint32_t state[5];
  if (input == NULL) {
    state[0] = 0x67452301;
    state[1] = 0xEFCDAB89;
    state[2] = 0x98BADCFE;
    state[3] = 0x10325476;
    state[4] = 0xC3D2E1F0;
    return (const char *)state; // Handle null input
  }

  static uint32_t w[80];
  memset(w, 0, sizeof(w));
  memcpy(w, input, 16 * sizeof(uint32_t));
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
  for (size_t i = 0; i < 16; ++i)
    w[i] = __builtin_bswap32(w[i]);
#endif
  for (size_t i = 16; i < 80; ++i)
    w[i] = S(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);

  uint32_t a = state[0], b = state[1], c = state[2], d = state[3], e = state[4];

  for (size_t i = 0; i < 80; ++i) {
    uint32_t f, k;
    if (i < 20)
      f = F1(b, c, d), k = 0x5A827999;
    else if (i < 40)
      f = F2(b, c, d), k = 0x6ED9EBA1;
    else if (i < 60)
      f = F3(b, c, d), k = 0x8F1BBCDC;
    else
      f = F4(b, c, d), k = 0xCA62C1D6;

    uint32_t temp = S(a, 5) + f + e + k + w[i];
    e = d, d = c, c = S(b, 30), b = a, a = temp;
  }

  state[0] += a, state[1] += b, state[2] += c, state[3] += d, state[4] += e;

  return (const char *)state; // Return the updated state as a string
}

char *sha1(const char *data, size_t len, char *buf) {
  size_t padded_len = len + 1 + (56 - (len + 1) % 64) % 64 + 8;
  uint8_t *padded = (uint8_t *)malloc(padded_len);
  if (!padded)
    return NULL;

  memcpy(padded, data, len);
  padded[len] = 0x80;
  memset(padded + len + 1, 0, padded_len - len - 1);
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
  uint64_t bit_len = __builtin_bswap64(len * 8);
#else
  uint64_t bit_len = len * 8;
#endif
  memcpy(padded + padded_len - 8, &bit_len, 8);

  const char *state = update_sha1(NULL); // Initialize SHA-1 state

  for (size_t i = 0; i < padded_len; i += 64)
    update_sha1((const uint32_t *)(padded + i));

  free(padded);

  memcpy(buf, state, 20); // Copy the final hash to the output buffer
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
  for (size_t i = 0; i < 5; ++i)
    ((uint32_t *)buf)[i] = __builtin_bswap32(((const uint32_t *)state)[i]);
#endif

  return buf; // Return the final hash as a string
}