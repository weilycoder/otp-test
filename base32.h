#ifndef BASE32_H
#define BASE32_H

#include <stdint.h>

extern const char base32_alphabet[];

size_t encode_size(size_t input_len);
size_t decode_size(const char *input);

char* b32encode(const char *input, size_t input_len, char *output);
char* b32decode(const char *input, size_t input_len, char *output);

#endif // BASE32_H
