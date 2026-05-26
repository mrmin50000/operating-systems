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

static unsigned char* master_key = nullptr;
static int master_key_len = 0;

__attribute__((destructor))
static void cleanup_master_key() {
    if (!master_key) return;
    mprotect(master_key, page_size, PROT_READ | PROT_WRITE);
    memset(master_key, 0, page_size);
    munmap(master_key, page_size);
    master_key = nullptr;
    master_key_len = 0;
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

void set_master_key(const unsigned char *key, int key_len) {
    if (!key || key_len <= 0) return;

    if (master_key) {
        mprotect(master_key, page_size, PROT_READ | PROT_WRITE);
        memset(master_key, 0, page_size);
        munmap(master_key, page_size);
    }

    master_key = (unsigned char*)mmap(nullptr, page_size,
                                      PROT_READ | PROT_WRITE,
                                      MAP_PRIVATE | MAP_ANONYMOUS,
                                      -1, 0);
    if (master_key == MAP_FAILED) {
        master_key = nullptr;
        return;
    }

    int copy_len = key_len < (int)page_size ? key_len : (int)page_size;
    memcpy(master_key, key, copy_len);
    master_key_len = copy_len;
    mprotect(master_key, page_size, PROT_READ);
}

void rc4_encrypt(unsigned char *data, int data_len,
                 const unsigned char *salt, int salt_len) {
    if (!master_key || !data || data_len <= 0) return;

    mprotect(master_key, page_size, PROT_READ | PROT_WRITE);

    unsigned char key_buf[256];
    int tmp_len = master_key_len;
    if (tmp_len > 256) tmp_len = 256;
    memcpy(key_buf, master_key, tmp_len);

    mprotect(master_key, page_size, PROT_READ);

    int full_key_len = tmp_len + salt_len;
    unsigned char full_key[256 + 16];
    memcpy(full_key, key_buf, tmp_len);
    if (salt && salt_len > 0)
        memcpy(full_key + tmp_len, salt, salt_len);

    memset(key_buf, 0, sizeof(key_buf));

    unsigned char S[256];
    for (int i = 0; i < 256; i++) S[i] = i;

    int j = 0;
    for (int i = 0; i < 256; i++) {
        j = (j + S[i] + full_key[i % full_key_len]) & 0xFF;
        unsigned char tmp = S[i];
        S[i] = S[j];
        S[j] = tmp;
    }

    int i = 0;
    j = 0;
    for (int n = 0; n < data_len; n++) {
        i = (i + 1) & 0xFF;
        j = (j + S[i]) & 0xFF;
        unsigned char tmp = S[i];
        S[i] = S[j];
        S[j] = tmp;
        unsigned char K = S[(S[i] + S[j]) & 0xFF];
        data[n] ^= K;
    }

    memset(S, 0, sizeof(S));
    memset(full_key, 0, sizeof(full_key));
}

}
