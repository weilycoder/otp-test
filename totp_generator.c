#include <stdio.h>
#include <time.h>

#include "otp.h"

int main(int argc, char *argv[]) {
  if (argc != 2) {
    fprintf(stderr, "Usage: totp <base32_key>\n");
    return 1;
  }

  const uint64_t T = time(NULL);
  uint32_t otp_value = otp(argv[1], T / 30);

  switch (otp_value) {
  case MEM_ALLOC_FAILED:
    fprintf(stderr, "Memory allocation failed\n");
    return 1;
  case BASE32_DECODE_FAILED:
    fprintf(stderr, "Base32 decode failed\n");
    return 1;
  case HMAC_FAILED:
    fprintf(stderr, "HMAC calculation failed\n");
    return 1;
  default:
    printf("Updating in %02u seconds\n", (unsigned)(30 - T % 30));
    printf("TOTP: %06u\n", otp(argv[1], T / 30) % 1000000);
    break;
  }

  return 0;
}