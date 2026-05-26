#ifndef XOR_H
#define XOR_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

void cipher(void *src, void *dst, int len);
void set_key(unsigned char k);
void probe_attack(void);
void set_master_key(const unsigned char *key, int key_len);
void rc4_encrypt(unsigned char *data, int data_len, const unsigned char *salt, int salt_len);

#ifdef __cplusplus
}
#endif

#endif
