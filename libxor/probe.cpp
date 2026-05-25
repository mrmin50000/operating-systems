#include <iostream>
#include <dlfcn.h>

typedef void (*set_key_func_t)(unsigned char);
typedef void (*probe_func_t)(void);

int main() {
    void *handle = dlopen("./libxor.so", RTLD_NOW);
    if (!handle) {
        std::cerr << "Error: " << dlerror() << "\n";
        return 1;
    }

    set_key_func_t set_key = (set_key_func_t)dlsym(handle, "set_key");
    probe_func_t probe_attack = (probe_func_t)dlsym(handle, "probe_attack");
    if (!set_key || !probe_attack) {
        std::cerr << "Error: symbols not found\n";
        dlclose(handle);
        return 1;
    }

    set_key(42);
    std::cerr << "Triggering probe_attack() — writing to PROT_READ page, SIGSEGV expected...\n";
    probe_attack();

    std::cerr << "ERROR: probe_attack() returned — write to protected page succeeded!\n";
    dlclose(handle);
    return 1;
}
