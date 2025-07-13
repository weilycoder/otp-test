#include "hmac.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

char *hmac(const char *K, size_t KL, const char *D, size_t DL, HashFunction H, size_t B, size_t L,
           char *output) {
  if (KL > B)
    return NULL; // Key is too long, cannot proceed

  char *K_pad = (char *)malloc((B + DL));
  if (!K_pad)
    return NULL; // Memory allocation failed

  memcpy(K_pad, K, KL);          // Copy key to K_pad
  memset(K_pad + KL, 0, B - KL); // Pad key with zeros
  memcpy(K_pad + B, D, DL);      // Append data to K_pad
  for (size_t i = 0; i < B; ++i)
    K_pad[i] ^= 0x36; // Inner padding

  char *inner_hash = (char *)malloc(L);
  if (!inner_hash)
    return free(K_pad), NULL; // Memory allocation failed

  H(K_pad, B + DL, inner_hash);
  free(K_pad);

  char *K_outer = (char *)malloc(B + L);
  if (!K_outer)
    return free(inner_hash), NULL; // Memory allocation failed

  memcpy(K_outer, K, KL);             // Copy key to K_outer
  memset(K_outer + KL, 0, B - KL);    // Pad key with zeros
  memcpy(K_outer + B, inner_hash, L); // Append inner hash to K_outer
  for (size_t i = 0; i < B; ++i)
    K_outer[i] ^= 0x5c; // Outer padding

  free(inner_hash);

  H(K_outer, B + L, output);
  free(K_outer);

  return output; // Return the final HMAC result
}
