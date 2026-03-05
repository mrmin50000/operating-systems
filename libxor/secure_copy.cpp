#include <iostream>
#include <fstream>
#include <cstring>
#include <cstdlib>
#include <dlfcn.h>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <csignal>
#include <vector>
#include <unistd.h>

const size_t BUFFER_SIZE = 4096;
const char* LIB_PATH = "./libxor.so";

volatile sig_atomic_t g_keep_running = 1;

const char* g_dst_file = nullptr;

typedef void (*cipher_func_t)(void*, void*, int);

struct SharedData {
    std::mutex mtx;
    std::condition_variable cv_producer;
    std::condition_variable cv_consumer;

    std::vector<char> buffer;
    size_t data_size = 0;
    bool eof_reached = false;

    size_t total_size = 0;
    size_t processed_size = 0;
    int last_progress_percent = -1;
};

void signal_handler(int signum) {
    if (signum == SIGINT) {
        g_keep_running = 0;
        
        if (g_dst_file != nullptr) {
            unlink(g_dst_file);
        }
    }
}

void update_progress(SharedData& shared, bool force = false) {
    if (shared.total_size == 0) return;

    int percent = static_cast<int>((shared.processed_size * 100) / shared.total_size);
    
    if (force || (percent / 10) != (shared.last_progress_percent / 10) || percent == 100) {
        shared.last_progress_percent = percent;
        
        int bar_width = 10;
        int filled = percent / 10;
        
        std::cerr << "\r[";
        for (int i = 0; i < bar_width; ++i) {
            if (i < filled) std::cerr << "=";
            else std::cerr << " ";
        }
        std::cerr << "] " << percent << "%";
        std::cerr.flush();
    }
}

void producer_thread(std::ifstream& src, SharedData& shared, cipher_func_t cipher) {
    std::vector<char> read_buf(BUFFER_SIZE);
    std::vector<char> enc_buf(BUFFER_SIZE);

    while (g_keep_running) {
        src.read(read_buf.data(), BUFFER_SIZE);
        std::streamsize bytes_read = src.gcount();

        if (bytes_read <= 0) {
            std::unique_lock<std::mutex> lock(shared.mtx);
            shared.eof_reached = true;
            shared.cv_consumer.notify_one();
            break;
        }

        cipher(read_buf.data(), enc_buf.data(), static_cast<int>(bytes_read));

        std::unique_lock<std::mutex> lock(shared.mtx);
        
        shared.cv_producer.wait_for(lock, std::chrono::milliseconds(100), [&shared]() {
            return shared.data_size == 0 || !g_keep_running;
        });

        if (!g_keep_running) break;

        memcpy(shared.buffer.data(), enc_buf.data(), bytes_read);
        shared.data_size = bytes_read;
        shared.processed_size += bytes_read;

        update_progress(shared);

        shared.cv_consumer.notify_one();
    }
}

void consumer_thread(std::ofstream& dst, SharedData& shared) {
    while (g_keep_running || !shared.eof_reached || shared.data_size > 0) {
        std::unique_lock<std::mutex> lock(shared.mtx);

        shared.cv_consumer.wait_for(lock, std::chrono::milliseconds(100), [&shared]() {
            return shared.data_size > 0 || shared.eof_reached || !g_keep_running;
        });

        if (!g_keep_running && shared.data_size == 0) break;
        if (shared.data_size == 0 && shared.eof_reached) break;

        if (shared.data_size > 0) {
            dst.write(shared.buffer.data(), shared.data_size);
            if (!dst) {
                std::cerr << "\nError writing to file!\n";
                g_keep_running = 0;
            }
            shared.data_size = 0;
        }

        shared.cv_producer.notify_one();
    }
}

void setup_signal_handler() {
    struct sigaction sa;
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, nullptr);
}

int main(int argc, char *argv[]) {
    if (argc != 4) {
        std::cerr << "Using: " << argv[0] << " <input_file> <output_file> <key>\n";
        return 1;
    }

    const char *src_file = argv[1];
    const char *dst_file = argv[2];
    int key = std::atoi(argv[3]);

    g_dst_file = dst_file;

    setup_signal_handler();

    void *handle = dlopen(LIB_PATH, RTLD_NOW);
    if (!handle) {
        std::cerr << "Lib download error: " << dlerror() << "\n";
        return 1;
    }

    unsigned char *lib_key = reinterpret_cast<unsigned char*>(dlsym(handle, "key"));
    if (!lib_key) {
        std::cerr << "Error: Not found 'key' in lib: " << dlerror() << "\n";
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
        std::cerr << "Error: src file doesnt exist '" << src_file << "'\n";
        dlclose(handle);
        return 1;
    }

    std::streamsize total_size = src.tellg();
    src.seekg(0, std::ios::beg);

    std::ofstream dst(dst_file, std::ios::binary);
    if (!dst) {
        std::cerr << "Error: dst file isnt created '" << dst_file << "'\n";
        dlclose(handle);
        return 1;
    }

    SharedData shared;
    shared.buffer.resize(BUFFER_SIZE);
    shared.total_size = static_cast<size_t>(total_size);
    shared.data_size = 0;
    shared.eof_reached = false;

    std::thread producer(producer_thread, std::ref(src), std::ref(shared), cipher);
    std::thread consumer(consumer_thread, std::ref(dst), std::ref(shared));

    producer.join();
    consumer.join();

    std::cerr << "\n";
    
    src.close();
    dst.close();
    dlclose(handle);

    if (!g_keep_running) {
        std::cout << "Keyboard interrupt" << std::endl;
        std::cout << "Output file has been deleted " << dst_file << std::endl;
        return 1;
    } else {
        std::cout << "Result: " << dst_file << std::endl;
        return 0;
    }
}
