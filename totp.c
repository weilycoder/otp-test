#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "base32.h"
#include "hotp.h"

int main(int argc, char *argv[]) {
  if (argc != 2) {
    fprintf(stderr, "Usage: totp <base32_key>\n");
    return 1;
  }

  const char *key = argv[1];
  size_t ds = decode_size(key);
  char *decoded_key = (char *)malloc(ds + 1);
  if (decoded_key == NULL)
    return fprintf(stderr, "Memory allocation failed\n"), 1;
  if (b32decode(key, strlen(key), decoded_key) == NULL)
    return free(decoded_key), fprintf(stderr, "Failed to decode base32 key\n"), 1;

  uint64_t T = time(NULL) / 30;
  uint32_t otp = hotp(decoded_key, strlen(decoded_key), T);
  printf("TOTP: %06u\n", otp % 1000000);
  return free(decoded_key), 0;
}