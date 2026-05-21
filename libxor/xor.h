#ifndef XOR_H
#define XOR_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

void cipher(void *src, void *dst, int len);
void set_key(unsigned char k);
void probe_attack(void);

#ifdef __cplusplus
}
#endif

#endif
