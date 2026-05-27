#include "xor.h"
#include <sys/mman.h>
#include <unistd.h>
#include <cstring>

static unsigned char* rc4_state = nullptr;
static size_t page_size = 0;

static void ensure_init() {
    if (page_size) return;
    page_size = sysconf(_SC_PAGESIZE);
    rc4_state = (unsigned char*)mmap(nullptr, page_size,
                                     PROT_READ | PROT_WRITE,
                                     MAP_PRIVATE | MAP_ANONYMOUS,
                                     -1, 0);
    if (rc4_state != MAP_FAILED) {
        memset(rc4_state, 0, page_size);
        mprotect(rc4_state, page_size, PROT_NONE);
    } else {
        rc4_state = nullptr;
    }
}

extern "C" {

void rc4_encrypt(unsigned char *data, int data_len,
                 const unsigned char *key, int key_len,
                 const unsigned char *salt, int salt_len) {
    if (!data || data_len <= 0 || !key || key_len <= 0) return;
    ensure_init();
    if (!rc4_state) return;

    mprotect(rc4_state, page_size, PROT_READ | PROT_WRITE);

    // Build full key on stack: key + salt, max 256 bytes
    int full_key_len = key_len + (salt && salt_len > 0 ? salt_len : 0);
    if (full_key_len > 256) full_key_len = 256;
    unsigned char full_key[256];
    int pos = 0;
    int n = key_len < full_key_len ? key_len : full_key_len;
    memcpy(full_key, key, n);
    pos += n;
    if (salt && salt_len > 0 && pos < full_key_len) {
        n = salt_len < full_key_len - pos ? salt_len : full_key_len - pos;
        memcpy(full_key + pos, salt, n);
    }

    // KSA
    for (int i = 0; i < 256; i++)
        rc4_state[i] = i;

    int j = 0;
    for (int i = 0; i < 256; i++) {
        j = (j + rc4_state[i] + full_key[i % full_key_len]) & 0xFF;
        rc4_state[i] ^= rc4_state[j];
        rc4_state[j] ^= rc4_state[i];
        rc4_state[i] ^= rc4_state[j];
    }

    memset(full_key, 0, sizeof(full_key));

    // i, j at the end of page
    unsigned char *i_ptr = rc4_state + page_size - 2;
    unsigned char *j_ptr = rc4_state + page_size - 1;
    *i_ptr = 0;
    *j_ptr = 0;

    // PRGA
    for (int n = 0; n < data_len; n++) {
        *i_ptr = (*i_ptr + 1) & 0xFF;
        *j_ptr = (*j_ptr + rc4_state[*i_ptr]) & 0xFF;
        rc4_state[*i_ptr] ^= rc4_state[*j_ptr];
        rc4_state[*j_ptr] ^= rc4_state[*i_ptr];
        rc4_state[*i_ptr] ^= rc4_state[*j_ptr];
        unsigned char K = rc4_state[(rc4_state[*i_ptr] + rc4_state[*j_ptr]) & 0xFF];
        data[n] ^= K;
    }

    mprotect(rc4_state, page_size, PROT_NONE);
}

void secure_cleanup(void) {
    if (!rc4_state) return;
    mprotect(rc4_state, page_size, PROT_READ | PROT_WRITE);
    memset(rc4_state, 0, page_size);
    munmap(rc4_state, page_size);
    rc4_state = nullptr;
    page_size = 0;
}

}
