#include <iostream>
#include <fstream>
#include <cstring>
#include <cstdlib>
#include <dlfcn.h>

typedef void (*cipher_func_t)(void*, void*, int);

void print_usage(const char *prog_name) {
    std::cerr << "Using: " << prog_name 
              << " <lib.so> <key> <src_file> <dst_file>\n";
}

int main(int argc, char *argv[]) {
    if (argc != 5) {
        print_usage(argv[0]);
        return 1;
    }

    const char *lib_path = argv[1];
    int key = std::atoi(argv[2]);
    const char *src_file = argv[3];
    const char *dst_file = argv[4];

    void *handle = dlopen(lib_path, RTLD_NOW);
    if (!handle) {
        std::cerr << "Lib download error: " << dlerror() << "\n";
        return 1;
    }

    unsigned char *lib_key = reinterpret_cast<unsigned char*>(dlsym(handle, "key"));
    if (!lib_key) {
        std::cerr << "Error: Not found 'key' int lib: " << dlerror() << "\n";
        dlclose(handle);
        return 1;
    }

    cipher_func_t cipher = reinterpret_cast<cipher_func_t>(dlsym(handle, "cipher"));
    if (!cipher) {
        std::cerr << "Error: not found 'cipher' in lib: " << dlerror() << "\n";
        dlclose(handle);
        return 1;
    }

    *lib_key = static_cast<unsigned char>(key);

    std::ifstream src(src_file, std::ios::binary | std::ios::ate);
    if (!src) {
        std::cerr << "Error: src file doesnt exist " << src_file << "'\n";
        dlclose(handle);
        return 1;
    }

    std::streamsize size = src.tellg();
    src.seekg(0, std::ios::beg);

    if (size <= 0) {
        std::cerr << "Error: src file is empty\n";
        dlclose(handle);
        return 1;
    }

    char *buffer = new char[size];
    if (!src.read(buffer, size)) {
        std::cerr << "Error: idk how read the file\n";
        delete[] buffer;
        dlclose(handle);
        return 1;
    }
    src.close();

    char *encrypted = new char[size];

    cipher(buffer, encrypted, static_cast<int>(size));

    std::ofstream dst(dst_file, std::ios::binary);
    if (!dst) {
        std::cerr << "Error: dst file isnt created" << dst_file << "'\n";
        delete[] buffer;
        delete[] encrypted;
        dlclose(handle);
        return 1;
    }

    dst.write(encrypted, size);
    if (!dst) {
        std::cerr << "Error: cant put in file\n";
        delete[] buffer;
        delete[] encrypted;
        dlclose(handle);
        return 1;
    }

    dst.close();

    delete[] buffer;
    delete[] encrypted;
    dlclose(handle);
    std::cout << "Result: " << dst_file << "\n";

    return 0;
}
