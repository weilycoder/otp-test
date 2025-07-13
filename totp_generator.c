#include <stdio.h>
#include <time.h>

#include "otp.h"

int main(int argc, char *argv[]) {
  if (argc != 2) {
    fprintf(stderr, "Usage: totp <base32_key>\n");
    return 1;
  }

  const char *key = argv[1];
  uint64_t T = time(NULL) / 30; // Time step of 30 seconds
  uint32_t otp_value = otp(key, T);

  printf("TOTP: %06u\n", otp_value % 1000000);
  return 0;
}