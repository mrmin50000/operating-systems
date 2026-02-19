#include "xor.h"

unsigned char key = 1;

extern "C" {

void cipher(void *src, void *dst, int len) {
  for (int i = 0; i < len; ++i) {
    ((char *)dst)[i] = ((char *)src)[i] ^ key;
  }
}
}
