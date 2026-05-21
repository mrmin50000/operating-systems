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
#include <sstream>

#ifndef WORKERS_COUNT
#define WORKERS_COUNT 4
#endif

const size_t BUFFER_SIZE = 4096;
const char* LIB_PATH = "./libxor.so";

enum ProcessMode {
    MODE_SEQUENTIAL,
    MODE_PARALLEL,
    MODE_AUTO
};

struct Stats {
    double total_time;
    double avg_time_per_file;
    int processed_count;
    std::vector<double> file_times;
};

struct SharedData {
    pthread_mutex_t queue_mutex;
    pthread_cond_t queue_cond;
    std::vector<std::string> files;
    size_t head_index;
    size_t tail_index;
    bool stop;
    int copied_count;
    std::string output_dir;
    int encryption_key;
    void* lib_handle;
    typedef void (*cipher_func_t)(void*, void*, int);
    cipher_func_t cipher;
    Stats stats;
};

int safe_lock_mutex(pthread_mutex_t* mutex, int timeout_sec) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += timeout_sec;
    int ret = pthread_mutex_timedlock(mutex, &ts);
    if (ret == ETIMEDOUT) {
        std::cerr << "\n[WARNING] Possible deadlock: thread waits for mutex more than " 
                  << timeout_sec << " seconds!\n";
        return -1;
    } else if (ret != 0) {
        std::cerr << "\n[ERROR] Mutex lock error: " << strerror(ret) << "\n";
        return -1;
    }
    return 0;
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

double get_time_ms() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1000000.0;
}

void* worker_thread(void* arg) {
    SharedData* data = (SharedData*)arg;
    
    while (true) {
        std::string current_file;
        
        pthread_mutex_lock(&data->queue_mutex);
        
        while (data->head_index >= data->files.size() && !data->stop) {
            pthread_cond_wait(&data->queue_cond, &data->queue_mutex);
        }
        
        if (data->head_index >= data->files.size() && data->stop) {
            pthread_mutex_unlock(&data->queue_mutex);
            break;
        }
        
        current_file = data->files[data->head_index];
        data->head_index++;
        
        pthread_mutex_unlock(&data->queue_mutex);
        
        double start_time = get_time_ms();
        bool success = process_file(current_file, data->output_dir, data);
        double end_time = get_time_ms();
        double file_time = end_time - start_time;
        
        pthread_mutex_lock(&data->queue_mutex);
        
        if (success) {
            data->copied_count++;
            data->stats.file_times.push_back(file_time);
        }
        
        pthread_mutex_unlock(&data->queue_mutex);
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

bool run_sequential(SharedData* data) {
    data->head_index = 0;
    data->stop = false;
    data->stats.total_time = 0.0;
    data->stats.processed_count = 0;
    data->copied_count = 0;
    data->stats.file_times.clear();
    
    double start_total = get_time_ms();
    
    for (size_t i = 0; i < data->files.size(); ++i) {
        double start_file = get_time_ms();
        bool success = process_file(data->files[i], data->output_dir, data);
        double end_file = get_time_ms();
        double file_time = end_file - start_file;
        
        if (success) {
            data->stats.processed_count++;
            data->copied_count++;
            data->stats.file_times.push_back(file_time);
        }
    }
    
    double end_total = get_time_ms();
    data->stats.total_time = end_total - start_total;
    
    if (data->stats.processed_count > 0) {
        data->stats.avg_time_per_file = data->stats.total_time / data->stats.processed_count;
    }
    
    return true;
}

bool run_parallel(SharedData* data) {
    data->head_index = 0;
    data->tail_index = data->files.size();
    data->stop = false;
    data->copied_count = 0;
    data->stats.file_times.clear();
    data->stats.processed_count = 0;
    
    pthread_mutex_init(&data->queue_mutex, nullptr);
    pthread_cond_init(&data->queue_cond, nullptr);
    
    double start_total = get_time_ms();
    
    pthread_t threads[WORKERS_COUNT];
    for (int i = 0; i < WORKERS_COUNT; ++i) {
        if (pthread_create(&threads[i], nullptr, worker_thread, data) != 0) {
            std::cerr << "Error: Failed to create thread " << i << "\n";
            return false;
        }
    }
    
    pthread_mutex_lock(&data->queue_mutex);
    data->stop = true;
    pthread_cond_broadcast(&data->queue_cond);
    pthread_mutex_unlock(&data->queue_mutex);
    
    for (int i = 0; i < WORKERS_COUNT; ++i) {
        pthread_join(threads[i], nullptr);
    }
    
    double end_total = get_time_ms();
    data->stats.total_time = end_total - start_total;
    data->stats.processed_count = data->copied_count;
    
    if (data->stats.processed_count > 0) {
        data->stats.avg_time_per_file = data->stats.total_time / data->stats.processed_count;
    }
    
    pthread_mutex_destroy(&data->queue_mutex);
    pthread_cond_destroy(&data->queue_cond);
    
    return true;
}

void print_stats(const std::string& mode_name, const Stats& stats) {
    std::cout << "\n========== " << mode_name << " Statistics ==========\n";
    std::cout << "Total execution time: " << std::fixed << std::setprecision(3) 
              << stats.total_time << " ms\n";
    std::cout << "Average time per file: " << std::fixed << std::setprecision(3) 
              << stats.avg_time_per_file << " ms\n";
    std::cout << "Files processed: " << stats.processed_count << "\n";
    std::cout << "=======================================\n";
}

ProcessMode parse_mode_arg(const std::string& arg) {
    if (arg == "--mode=sequential") return MODE_SEQUENTIAL;
    if (arg == "--mode=parallel") return MODE_PARALLEL;
    if (arg == "--mode=auto") return MODE_AUTO;
    return MODE_AUTO;
}

int main(int argc, char *argv[]) {
    if (argc < 4) {
        std::cerr << "Usage: " << argv[0] 
                  << " [--mode=sequential|--mode=parallel|--mode=auto] "
                  << "file1.txt [file2.txt ...] output_dir key\n";
        return 1;
    }

    ProcessMode mode = MODE_AUTO;
    int key = 1;
    std::string output_dir;
    std::vector<std::string> input_files;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg.substr(0, 7) == "--mode=") {
            mode = parse_mode_arg(arg);
        } else if (arg == "-k" && i + 1 < argc) {
            key = std::atoi(argv[++i]);
        }
    }

    for (int i = 1; i < argc - 2; ++i) {
        struct stat st;
        if (stat(argv[i], &st) == 0 && (S_ISREG(st.st_mode) || S_ISCHR(st.st_mode))) {
            input_files.push_back(argv[i]);
        }
    }

    output_dir = argv[argc - 2];
    key = std::atoi(argv[argc - 1]);

    if (input_files.empty()) {
        std::cerr << "Error: No input files specified\n";
        return 1;
    }

    if (!create_directory(output_dir)) {
        return 1;
    }

    ProcessMode selected_mode = mode;

    if (mode == MODE_AUTO) {
        if (input_files.size() < 5) {
            selected_mode = MODE_SEQUENTIAL;
        } else {
            selected_mode = MODE_PARALLEL;
        }
    }

    void* handle = dlopen(LIB_PATH, RTLD_NOW);
    if (!handle) {
        std::cerr << "Lib download error: " << dlerror() << "\n";
        return 1;
    }

    typedef void (*cipher_func_t)(void*, void*, int);
    cipher_func_t cipher = reinterpret_cast<cipher_func_t>(dlsym(handle, "cipher"));
    if (!cipher) {
        std::cerr << "Error: not found 'cipher' in lib: " << dlerror() << "\n";
        dlclose(handle);
        return 1;
    }

    typedef void (*set_key_func_t)(unsigned char);
    set_key_func_t set_key = reinterpret_cast<set_key_func_t>(dlsym(handle, "set_key"));
    if (!set_key) {
        std::cerr << "Error: not found 'set_key' in lib: " << dlerror() << "\n";
        dlclose(handle);
        return 1;
    }

    set_key(static_cast<unsigned char>(key));

    SharedData data;
    data.files = input_files;
    data.output_dir = output_dir;
    data.encryption_key = key;
    data.lib_handle = handle;
    data.cipher = cipher;
    data.copied_count = 0;

    double seq_time = 0, par_time = 0;

    if (selected_mode == MODE_SEQUENTIAL) {
        std::cout << "Running in SEQUENTIAL mode (" << input_files.size() << " files)\n";
        data.head_index = 0;
        data.stop = false;
        data.copied_count = 0;
        run_sequential(&data);
        seq_time = data.stats.total_time;
        print_stats("SEQUENTIAL", data.stats);
    } else if (selected_mode == MODE_PARALLEL) {
        std::cout << "Running in PARALLEL mode (" << input_files.size() 
                 << " files, " << WORKERS_COUNT << " workers)\n";
        data.head_index = 0;
        data.stop = false;
        data.copied_count = 0;
        run_parallel(&data);
        par_time = data.stats.total_time;
        print_stats("PARALLEL", data.stats);
    }

    if (mode == MODE_AUTO) {
        std::cout << "Running in " << (selected_mode == MODE_SEQUENTIAL ? "PARALLEL" : "SEQUENTIAL") 
                  << " mode to compare...\n";
        
        if (selected_mode == MODE_SEQUENTIAL) {
            data.head_index = 0;
            data.stop = false;
            data.copied_count = 0;
            run_parallel(&data);
            par_time = data.stats.total_time;
            print_stats("PARALLEL (comparison)", data.stats);
        } else {
            data.head_index = 0;
            data.stop = false;
            data.copied_count = 0;
            run_sequential(&data);
            seq_time = data.stats.total_time;
            print_stats("SEQUENTIAL (comparison)", data.stats);
        }

        std::cout << "\n========== Comparison ==========\n";
        std::cout << "Selected mode: " 
                 << (selected_mode == MODE_SEQUENTIAL ? "SEQUENTIAL" : "PARALLEL") << "\n";
        std::cout << "Because: file count (" << input_files.size() 
                 << ") " << (input_files.size() < 5 ? "<" : ">=") << " 5\n";
        std::cout << "Sequential time: " << std::fixed << std::setprecision(3) 
                  << seq_time << " ms\n";
        std::cout << "Parallel time: " << std::fixed << std::setprecision(3) 
                  << par_time << " ms\n";
        std::cout << "Speedup: " << std::fixed << std::setprecision(2) 
                  << (par_time > 0 ? seq_time / par_time : 0) << "x\n";
        std::cout << "================================\n";
    }

    dlclose(handle);

    return 0;
}