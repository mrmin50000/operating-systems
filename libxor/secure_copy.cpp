#define _POSIX_C_SOURCE 200809L
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <dlfcn.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <ctime>
#include <errno.h>
#include <iomanip>

const size_t BUFFER_SIZE = 4096;
const char* LIB_PATH = "./libxor.so";
const int MUTEX_TIMEOUT_SEC = 5;
const int NUM_WORKER_THREADS = 3;

struct SharedData {
    pthread_mutex_t global_mutex;
    std::vector<std::string> files;
    size_t next_file_index;
    int copied_count;
    std::string output_dir;
    int encryption_key;
    
    void* lib_handle;
    unsigned char* lib_key;
    typedef void (*cipher_func_t)(void*, void*, int);
    cipher_func_t cipher;
};

SharedData g_data;

int safe_lock_mutex(pthread_mutex_t* mutex) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += MUTEX_TIMEOUT_SEC;

    int ret = pthread_mutex_timedlock(mutex, &ts);
    if (ret == ETIMEDOUT) {
        std::cerr << "\n[WARNING] Possible deadlock: thread waits for mutex more than " 
                  << MUTEX_TIMEOUT_SEC << " seconds!\n";
        return -1;
    } else if (ret != 0) {
        std::cerr << "\n[ERROR] Mutex lock error: " << strerror(ret) << "\n";
        return -1;
    }
    return 0;
}

void log_operation_locked(const std::string& filename, bool success, double exec_time) {
    std::ofstream log_file("log.txt", std::ios::app);
    if (!log_file.is_open()) {
        std::cerr << "Error: Cannot open log.txt\n";
        return;
    }

    time_t now = time(0);
    struct tm* ltm = localtime(&now);
    char time_buf[64];
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", ltm);

    unsigned long tid = (unsigned long)pthread_self();

    std::string result = success ? "SUCCESS" : "ERROR";

    log_file << "[" << time_buf << "] "
             << "Thread-" << tid << " | "
             << "File: " << filename << " | "
             << "Result: " << result << " | "
             << "Time: " << std::fixed << std::setprecision(3) << exec_time << "s"
             << std::endl;
    
    log_file.close();
}

bool process_file(const std::string& input_path, const std::string& output_dir, 
                  SharedData* data) {
    size_t pos = input_path.find_last_of("/\\");
    std::string filename = (pos != std::string::npos) ? input_path.substr(pos + 1) : input_path;
    std::string output_path = output_dir + "/" + filename;

    std::ifstream src(input_path, std::ios::binary);
    if (!src) {
        return false;
    }

    std::ofstream dst(output_path, std::ios::binary);
    if (!dst) {
        return false;
    }

    std::vector<char> buffer(BUFFER_SIZE);
    std::vector<char> enc_buffer(BUFFER_SIZE);

    while (src) {
        src.read(buffer.data(), BUFFER_SIZE);
        std::streamsize bytes_read = src.gcount();
        if (bytes_read > 0) {
            data->cipher(buffer.data(), enc_buffer.data(), static_cast<int>(bytes_read));
            dst.write(enc_buffer.data(), bytes_read);
            if (!dst) return false;
        }
    }

    src.close();
    dst.close();
    return true;
}

void* worker_thread(void* arg) {
    SharedData* data = (SharedData*)arg;
    
    while (true) {
        std::string current_file;
        size_t file_index = 0;

        if (safe_lock_mutex(&data->global_mutex) != 0) {
            return nullptr; // Timeout or error
        }

        if (data->next_file_index < data->files.size()) {
            file_index = data->next_file_index;
            current_file = data->files[data->next_file_index];
            data->next_file_index++;
        }
        
        pthread_mutex_unlock(&data->global_mutex);

        if (current_file.empty()) {
            break;
        }

        clock_t start_time = clock();
        bool success = process_file(current_file, data->output_dir, data);
        clock_t end_time = clock();
        double exec_time = static_cast<double>(end_time - start_time) / CLOCKS_PER_SEC;

        if (safe_lock_mutex(&data->global_mutex) != 0) {
            return nullptr;
        }

        if (success) {
            data->copied_count++;
        }
        log_operation_locked(current_file, success, exec_time);

        pthread_mutex_unlock(&data->global_mutex);
    }

    return nullptr;
}

bool create_directory(const std::string& path) {
    struct stat st;
    if (stat(path.c_str(), &st) != 0) {
        if (mkdir(path.c_str(), 0777) != 0) {
            std::cerr << "Error: Cannot create directory " << path << "\n";
            return false;
        }
    } else if (!S_ISDIR(st.st_mode)) {
        std::cerr << "Error: " << path << " exists but is not a directory\n";
        return false;
    }
    return true;
}

int main(int argc, char *argv[]) {
    if (argc < 4) {
        std::cerr << "Usage: " << argv[0] << " file1.txt [file2.txt ...] output_dir key\n";
        return 1;
    }

    std::string output_dir = argv[argc - 2];
    std::string key_str = argv[argc - 1];
    int encryption_key = std::atoi(key_str.c_str());

    std::vector<std::string> input_files;
    for (int i = 1; i < argc - 2; ++i) {
        input_files.push_back(argv[i]);
    }

    if (input_files.empty()) {
        std::cerr << "Error: No input files specified\n";
        return 1;
    }

    if (!create_directory(output_dir)) {
        return 1;
    }

    void* handle = dlopen(LIB_PATH, RTLD_NOW);
    if (!handle) {
        std::cerr << "Lib download error: " << dlerror() << "\n";
        return 1;
    }

    unsigned char* lib_key = reinterpret_cast<unsigned char*>(dlsym(handle, "key"));
    if (!lib_key) {
        std::cerr << "Error: Not found 'key' in lib: " << dlerror() << "\n";
        dlclose(handle);
        return 1;
    }

    typedef void (*cipher_func_t)(void*, void*, int);
    cipher_func_t cipher = reinterpret_cast<cipher_func_t>(dlsym(handle, "cipher"));
    if (!cipher) {
        std::cerr << "Error: not found 'cipher' in lib: " << dlerror() << "\n";
        dlclose(handle);
        return 1;
    }

    *lib_key = static_cast<unsigned char>(encryption_key);

    g_data.files = input_files;
    g_data.next_file_index = 0;
    g_data.copied_count = 0;
    g_data.output_dir = output_dir;
    g_data.encryption_key = encryption_key;
    g_data.lib_handle = handle;
    g_data.lib_key = lib_key;
    g_data.cipher = cipher;

    pthread_mutex_init(&g_data.global_mutex, nullptr);

    pthread_t threads[NUM_WORKER_THREADS];
    std::cout << "Starting " << NUM_WORKER_THREADS << " worker threads...\n";
    
    for (int i = 0; i < NUM_WORKER_THREADS; ++i) {
        if (pthread_create(&threads[i], nullptr, worker_thread, &g_data) != 0) {
            std::cerr << "Error: Failed to create thread " << i << "\n";
            return 1;
        }
    }

    for (int i = 0; i < NUM_WORKER_THREADS; ++i) {
        pthread_join(threads[i], nullptr);
    }

    std::cout << "\nProcessing completed.\n";
    std::cout << "Total files copied: " << g_data.copied_count << " / " << input_files.size() << "\n";
    std::cout << "Check log.txt for details.\n";

    pthread_mutex_destroy(&g_data.global_mutex);
    dlclose(handle);

    return 0;
}
