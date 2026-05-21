#include "xor.h"
#include <sys/mman.h>
#include <unistd.h>
#include <pthread.h>
#include <cstring>
#include <cstdlib>
#include <iostream>

#ifdef DEBUG_KEY
#define KEY_LOG(msg) std::cerr << "[KEY] " << msg << "\n"
#else
#define KEY_LOG(msg)
#endif

static unsigned char* secure_key = nullptr;
static size_t page_size = 0;
static pthread_mutex_t key_mutex = PTHREAD_MUTEX_INITIALIZER;

__attribute__((constructor))
static void init_key_storage() {
    page_size = sysconf(_SC_PAGESIZE);
    secure_key = (unsigned char*)mmap(nullptr, page_size,
                                      PROT_READ | PROT_WRITE,
                                      MAP_PRIVATE | MAP_ANONYMOUS,
                                      -1, 0);
    if (secure_key == MAP_FAILED) {
        secure_key = nullptr;
        return;
    }
    KEY_LOG("mmap at " << (void*)secure_key);
    *secure_key = 1;
    mprotect(secure_key, page_size, PROT_NONE);
    KEY_LOG("mprotect: RW -> NONE (init)");
}

__attribute__((destructor))
static void cleanup_key_storage() {
    if (!secure_key) return;
    mprotect(secure_key, page_size, PROT_READ | PROT_WRITE);
    KEY_LOG("mprotect: NONE -> RW (cleanup)");
    *secure_key = 0;
    KEY_LOG("key zeroed");
    munmap(secure_key, page_size);
    KEY_LOG("munmap at " << (void*)secure_key);
    secure_key = nullptr;
}

extern "C" {

void cipher(void *src, void *dst, int len) {
    if (!secure_key) return;

    pthread_mutex_lock(&key_mutex);
    mprotect(secure_key, page_size, PROT_READ);

    for (int i = 0; i < len; ++i) {
        ((char *)dst)[i] = ((char *)src)[i] ^ *secure_key;
    }

    mprotect(secure_key, page_size, PROT_NONE);
    pthread_mutex_unlock(&key_mutex);
}

void probe_attack(void) {
    if (!secure_key) return;

    volatile unsigned char leak = *secure_key;
    (void)leak;
}

void set_key(unsigned char k) {
    if (!secure_key) return;

    pthread_mutex_lock(&key_mutex);
    mprotect(secure_key, page_size, PROT_READ | PROT_WRITE);
    KEY_LOG("mprotect: NONE -> RW (set_key)");
    *secure_key = k;
    mprotect(secure_key, page_size, PROT_NONE);
    KEY_LOG("mprotect: RW -> NONE (set_key)");
    pthread_mutex_unlock(&key_mutex);
}

}
