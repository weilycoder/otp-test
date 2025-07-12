#include "base32.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

const char base32_alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

static size_t from_b32code(char c) {
  if (c >= 'A' && c <= 'Z')
    return c - 'A';
  if (c >= 'a' && c <= 'z')
    return c - 'a';
  if (c >= '2' && c <= '7')
    return c - '2' + 26;
  return 32; // Invalid character
}

size_t encode_size(size_t input_len) {
  return (input_len + 4) / 5 * 8; // Base32 encodes every 5 bytes to 8 characters
}

size_t decode_size(const char *input) {
  size_t len = 0;
  while (input[len] && input[len] != '=')
    len++;
  return (len * 5 + 7) / 8; // Base32 decodes every 8 characters to 5 bytes
}

char *b32encode(const char *input, size_t input_len, char *output) {
  size_t output_len = encode_size(input_len);
  size_t i, j;
  for (i = 0, j = 0; i < input_len;) {
    size_t buffer = 0, bits = 0;
    for (; i < input_len && bits < 40; i++, bits += 8)
      buffer = (buffer << 8) | (unsigned char)input[i];
    for (; bits >= 5; bits -= 5)
      output[j++] = base32_alphabet[(buffer >> (bits - 5)) & 0x1F];
    if (bits > 0)
      output[j++] = base32_alphabet[(buffer << (5 - bits)) & 0x1F];
  }
  for (; j < output_len; j++)
    output[j] = '=';         // Padding with '='
  output[output_len] = '\0'; // Null-terminate the output string
  return output;
}

char *b32decode(const char *input, size_t input_len, char *output) {
  size_t i, j;
  for (i = 0, j = 0; i < input_len && input[i] != '=';) {
    size_t buffer = 0, bits = 0;
    for (; i < input_len && input[i] != '=' && bits < 40; i++, bits += 5) {
      size_t value = from_b32code(input[i]);
      if (value == 32)
        return NULL; // Invalid character
      buffer = (buffer << 5) | value;
    }
    for (; bits >= 8; bits -= 8)
      output[j++] = (buffer >> (bits - 8)) & 0xFF;
    if (bits > 0 && (buffer & ((1 << bits) - 1)) != 0)
      return NULL; // Incomplete byte
  }
  output[j] = '\0'; // Null-terminate the output string
  return output;
}