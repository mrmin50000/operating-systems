#include "xor.h"
#include <sys/mman.h>
#include <unistd.h>
#include <pthread.h>
#include <cstring>
#include <cstdlib>
#include <iostream>
#include <signal.h>

#ifdef DEBUG_KEY
#define KEY_LOG(msg) std::cerr << "[KEY] " << msg << "\n"
#else
#define KEY_LOG(msg)
#endif

static const size_t KEY_SIZE = 16;
static unsigned char* secure_key = nullptr;
static size_t page_size = 0;
static pthread_mutex_t key_mutex = PTHREAD_MUTEX_INITIALIZER;
static struct sigaction old_sa;

static void segv_handler(int sig, siginfo_t *info, void *ctx) {
    (void)sig;
    (void)ctx;
    if (secure_key && info->si_addr >= (void*)secure_key && info->si_addr < (void*)(secure_key + KEY_SIZE)) {
        std::cerr << "[SECURITY] Attempt to access protected key memory at address "
                  << info->si_addr << ". Aborting...\n";
        _exit(1);
    }
    sigaction(SIGSEGV, &old_sa, nullptr);
    raise(SIGSEGV);
}

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

    unsigned char init_key = 1;
    memcpy(secure_key, &init_key, 1);
    mprotect(secure_key, KEY_SIZE, PROT_READ);
    KEY_LOG("mprotect: RW -> READ (init)");

    struct sigaction sa;
    sa.sa_sigaction = segv_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGSEGV, &sa, &old_sa);
}

__attribute__((destructor))
static void cleanup_key_storage() {
    if (!secure_key) return;

    sigaction(SIGSEGV, &old_sa, nullptr);

    mprotect(secure_key, KEY_SIZE, PROT_READ | PROT_WRITE);
    KEY_LOG("mprotect: READ -> RW (cleanup)");
    memset(secure_key, 0, KEY_SIZE);
    KEY_LOG("key zeroed");
    mprotect(secure_key, KEY_SIZE, PROT_READ);
    KEY_LOG("mprotect: RW -> READ (cleanup post-zero)");
    munmap(secure_key, page_size);
    KEY_LOG("munmap at " << (void*)secure_key);
    secure_key = nullptr;
}

extern "C" {

void cipher(void *src, void *dst, int len) {
    if (!secure_key) return;

    pthread_mutex_lock(&key_mutex);
    mprotect(secure_key, KEY_SIZE, PROT_READ | PROT_WRITE);
    KEY_LOG("mprotect: READ -> RW (cipher)");

    unsigned char k;
    memcpy(&k, secure_key, 1);
    mprotect(secure_key, KEY_SIZE, PROT_READ);
    KEY_LOG("mprotect: RW -> READ (cipher)");

    for (int i = 0; i < len; ++i) {
        ((char *)dst)[i] = ((char *)src)[i] ^ k;
    }

    k = 0;

    pthread_mutex_unlock(&key_mutex);
}

void probe_attack(void) {
    if (!secure_key) return;

    volatile unsigned char *p = secure_key;
    *p = 0xFF;
}

void set_key(unsigned char k) {
    if (!secure_key) return;

    pthread_mutex_lock(&key_mutex);
    mprotect(secure_key, KEY_SIZE, PROT_READ | PROT_WRITE);
    KEY_LOG("mprotect: READ -> RW (set_key)");
    memcpy(secure_key, &k, 1);
    mprotect(secure_key, KEY_SIZE, PROT_READ);
    KEY_LOG("mprotect: RW -> READ (set_key)");
    pthread_mutex_unlock(&key_mutex);
}

}
