#include "xor.h"
#include <sys/mman.h>
#include <unistd.h>
#include <cstring>

struct RC4Ctx {
    unsigned char* state = nullptr;
    size_t page_size = 0;

    RC4Ctx() = default;

    RC4Ctx(const RC4Ctx&) = delete;
    RC4Ctx& operator=(const RC4Ctx&) = delete;

    ~RC4Ctx() {
        if (state) {
            mprotect(state, page_size, PROT_READ | PROT_WRITE);
            memset(state, 0, page_size);
            munmap(state, page_size);
        }
    }
};

static thread_local RC4Ctx r;

static void ensure_init() {
    if (r.page_size) return;
    r.page_size = sysconf(_SC_PAGESIZE);
    r.state = (unsigned char*)mmap(nullptr, r.page_size,
                                   PROT_READ | PROT_WRITE,
                                   MAP_PRIVATE | MAP_ANONYMOUS,
                                   -1, 0);
    if (r.state != MAP_FAILED) {
        memset(r.state, 0, r.page_size);
        mprotect(r.state, r.page_size, PROT_NONE);
    } else {
        r.state = nullptr;
    }
}

extern "C" {

void rc4_encrypt(unsigned char *data, int data_len,
                 const unsigned char *key, int key_len,
                 const unsigned char *salt, int salt_len) {
    if (!data || data_len <= 0 || !key || key_len <= 0) return;
    ensure_init();
    if (!r.state) return;

    mprotect(r.state, r.page_size, PROT_READ | PROT_WRITE);

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
        r.state[i] = i;

    int j = 0;
    for (int i = 0; i < 256; i++) {
        j = (j + r.state[i] + full_key[i % full_key_len]) & 0xFF;
        if (i != j) {
            r.state[i] ^= r.state[j];
            r.state[j] ^= r.state[i];
            r.state[i] ^= r.state[j];
        }
    }

    memset(full_key, 0, sizeof(full_key));

    // i, j at the end of page
    unsigned char *i_ptr = r.state + r.page_size - 2;
    unsigned char *j_ptr = r.state + r.page_size - 1;
    *i_ptr = 0;
    *j_ptr = 0;

    // PRGA
    for (int n = 0; n < data_len; n++) {
        *i_ptr = (*i_ptr + 1) & 0xFF;
        *j_ptr = (*j_ptr + r.state[*i_ptr]) & 0xFF;
        if (*i_ptr != *j_ptr) {
            r.state[*i_ptr] ^= r.state[*j_ptr];
            r.state[*j_ptr] ^= r.state[*i_ptr];
            r.state[*i_ptr] ^= r.state[*j_ptr];
        }
        unsigned char K = r.state[(r.state[*i_ptr] + r.state[*j_ptr]) & 0xFF];
        data[n] ^= K;
    }

    mprotect(r.state, r.page_size, PROT_NONE);
}

void secure_cleanup(void) {
    // Each thread owns its own thread_local RC4Ctx, which cleans up in its destructor.
    // This function is kept for API compatibility.
    // To force cleanup, threads must be joined and the thread_local storage destroyed.
}

}
