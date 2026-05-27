#ifndef XOR_H
#define XOR_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

void rc4_encrypt(unsigned char *data, int data_len,
                 const unsigned char *key, int key_len,
                 const unsigned char *salt, int salt_len);

#ifdef __cplusplus
}
#endif

#endif
