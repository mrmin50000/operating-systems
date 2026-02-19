#ifndef XOR_H
#define XOR_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

void cipher(void *src, void *dst, int len);

#ifdef __cplusplus
}
#endif

#endif
