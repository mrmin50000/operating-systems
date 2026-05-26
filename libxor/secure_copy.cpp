#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstring>
#include <cstdlib>
#include <cstdint>
#include <dlfcn.h>
#include <pthread.h>
#include <sys/stat.h>
#include <dirent.h>
#include <algorithm>
#include <unistd.h>
#include <fcntl.h>

const int MAX_THREADS = 5;
const int SALT_SIZE = 16;
const char* LIB_PATH = "./libxor.so";

#pragma pack(push, 1)
struct ImageRecord {
    uint32_t file_len;
    uint32_t name_len;
    unsigned char salt[SALT_SIZE];
};
#pragma pack(pop)

typedef void (*set_master_key_func_t)(const unsigned char*, int);
typedef void (*rc4_encrypt_func_t)(unsigned char*, int, const unsigned char*, int);

struct Args {
    bool add = false;
    bool list = false;
    bool get = false;
    std::string key;
    std::string image;
    std::string out;
    std::vector<std::string> paths;
    std::string get_filename;
};

struct AddJob {
    std::string file_path;
    std::string rel_name;
};

struct AddData {
    std::vector<AddJob> jobs;
    std::string image_path;
    pthread_mutex_t queue_mutex;
    pthread_mutex_t image_mutex;
    pthread_cond_t queue_cond;
    size_t head_index;
    bool stop;
    rc4_encrypt_func_t rc4_encrypt;
    int errors;
    int added;
};

static void collect_files(const std::string &dir_path, const std::string &base,
                          std::vector<AddJob> &jobs) {
    DIR *dir = opendir(dir_path.c_str());
    if (!dir) {
        std::cerr << "Error: cannot open directory " << dir_path << "\n";
        return;
    }
    struct dirent *entry;
    while ((entry = readdir(dir)) != nullptr) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;
        std::string full = dir_path + "/" + entry->d_name;
        struct stat st;
        if (stat(full.c_str(), &st) != 0) continue;
        std::string rel = base + "/" + entry->d_name;
        if (S_ISDIR(st.st_mode)) {
            collect_files(full, rel, jobs);
        } else if (S_ISREG(st.st_mode)) {
            jobs.push_back({full, rel});
        }
    }
    closedir(dir);
}

static bool write_record(std::ofstream &img, const std::string &name,
                         const unsigned char *salt,
                         const unsigned char *content, uint32_t content_len) {
    uint32_t name_len = (uint32_t)name.size();
    ImageRecord rec;
    rec.file_len = content_len;
    rec.name_len = name_len;
    memcpy(rec.salt, salt, SALT_SIZE);

    img.write((const char*)&rec, sizeof(rec));
    if (!img) return false;
    img.write(name.data(), name_len);
    if (!img) return false;
    img.write((const char*)content, content_len);
    if (!img) return false;
    return true;
}

static bool read_record(std::ifstream &img, std::string &name,
                        std::vector<unsigned char> &salt,
                        std::vector<unsigned char> &content) {
    ImageRecord rec;
    img.read((char*)&rec, sizeof(rec));
    if (img.gcount() == 0) return false;
    if (img.gcount() != sizeof(rec)) return false;

    name.resize(rec.name_len);
    img.read(&name[0], rec.name_len);
    if ((size_t)img.gcount() != rec.name_len) return false;

    content.resize(rec.file_len);
    img.read((char*)content.data(), rec.file_len);
    if ((size_t)img.gcount() != rec.file_len) return false;

    salt.resize(SALT_SIZE);
    memcpy(salt.data(), rec.salt, SALT_SIZE);

    return true;
}

static void* add_worker(void *arg) {
    AddData *data = (AddData*)arg;
    std::vector<char> buf;
    buf.reserve(65536);

    while (true) {
        pthread_mutex_lock(&data->queue_mutex);
        while (data->head_index >= data->jobs.size() && !data->stop) {
            pthread_cond_wait(&data->queue_cond, &data->queue_mutex);
        }
        if (data->head_index >= data->jobs.size() && data->stop) {
            pthread_mutex_unlock(&data->queue_mutex);
            break;
        }
        AddJob job = data->jobs[data->head_index];
        data->head_index++;
        pthread_mutex_unlock(&data->queue_mutex);

        // Read file
        std::ifstream src(job.file_path, std::ios::binary);
        if (!src) {
            std::cerr << "Error: cannot read " << job.file_path << "\n";
            __sync_fetch_and_add(&data->errors, 1);
            continue;
        }
        src.seekg(0, std::ios::end);
        size_t file_size = src.tellg();
        src.seekg(0, std::ios::beg);
        buf.resize(file_size);
        src.read(buf.data(), file_size);
        if ((size_t)src.gcount() != file_size) {
            std::cerr << "Error: short read " << job.file_path << "\n";
            __sync_fetch_and_add(&data->errors, 1);
            continue;
        }
        src.close();

        // Generate salt
        unsigned char salt[SALT_SIZE];
        int fd = open("/dev/urandom", O_RDONLY);
        if (fd < 0 || read(fd, salt, SALT_SIZE) != SALT_SIZE) {
            std::cerr << "Error: cannot generate salt\n";
            if (fd >= 0) close(fd);
            __sync_fetch_and_add(&data->errors, 1);
            continue;
        }
        close(fd);

        // Encrypt (master_key already set by do_add)
        data->rc4_encrypt((unsigned char*)buf.data(), (int)file_size, salt, SALT_SIZE);

        // Write to image
        pthread_mutex_lock(&data->image_mutex);
        std::ofstream img(data->image_path,
                          std::ios::binary | std::ios::app);
        if (!img) {
            std::cerr << "Error: cannot open image " << data->image_path << "\n";
            pthread_mutex_unlock(&data->image_mutex);
            __sync_fetch_and_add(&data->errors, 1);
            continue;
        }
        bool ok = write_record(img, job.rel_name, salt,
                               (unsigned char*)buf.data(), (uint32_t)file_size);
        img.close();
        pthread_mutex_unlock(&data->image_mutex);

        if (!ok) {
            std::cerr << "Error: cannot write " << job.rel_name << " to image\n";
            __sync_fetch_and_add(&data->errors, 1);
            continue;
        }
        __sync_fetch_and_add(&data->added, 1);
        std::cout << "  added " << job.rel_name << " (" << file_size << " bytes)\n";
    }
    return nullptr;
}

static bool do_add(Args &args) {
    std::vector<AddJob> jobs;
    for (const auto &p : args.paths) {
        struct stat st;
        if (stat(p.c_str(), &st) != 0) {
            std::cerr << "Error: path not found " << p << "\n";
            continue;
        }
        if (S_ISDIR(st.st_mode)) {
            collect_files(p, p, jobs);
        } else if (S_ISREG(st.st_mode)) {
            size_t pos = p.find_last_of("/\\");
            std::string name = (pos != std::string::npos) ? p.substr(pos + 1) : p;
            jobs.push_back({p, name});
        }
    }

    if (jobs.empty()) {
        std::cerr << "Error: no files to add\n";
        return false;
    }

    // Open image for append (create if doesn't exist)
    bool exists = (access(args.image.c_str(), F_OK) == 0);
    std::ofstream img(args.image, std::ios::binary | std::ios::app);
    if (!img) {
        std::cerr << "Error: cannot create/open image " << args.image << "\n";
        return false;
    }
    img.close();

    // Load libxor and get function pointers
    void *handle = dlopen(LIB_PATH, RTLD_NOW);
    if (!handle) {
        std::cerr << "Error: " << dlerror() << "\n";
        return false;
    }

    auto set_master_key = (set_master_key_func_t)dlsym(handle, "set_master_key");
    auto rc4_encrypt = (rc4_encrypt_func_t)dlsym(handle, "rc4_encrypt");
    if (!set_master_key || !rc4_encrypt) {
        std::cerr << "Error: symbols not found in " << LIB_PATH << "\n";
        dlclose(handle);
        return false;
    }

    set_master_key((const unsigned char*)args.key.data(), (int)args.key.size());

    AddData data;
    data.jobs = std::move(jobs);
    data.image_path = args.image;
    data.head_index = 0;
    data.stop = false;
    data.rc4_encrypt = rc4_encrypt;
    data.errors = 0;
    data.added = 0;

    pthread_mutex_init(&data.queue_mutex, nullptr);
    pthread_mutex_init(&data.image_mutex, nullptr);
    pthread_cond_init(&data.queue_cond, nullptr);

    int thread_count = data.jobs.size() < (size_t)MAX_THREADS
                       ? (int)data.jobs.size() : MAX_THREADS;

    std::cout << "Adding " << data.jobs.size() << " file(s) with "
              << thread_count << " thread(s)...\n";

    std::vector<pthread_t> threads(thread_count);
    for (int i = 0; i < thread_count; i++) {
        pthread_create(&threads[i], nullptr, add_worker, &data);
    }

    pthread_mutex_lock(&data.queue_mutex);
    data.stop = true;
    pthread_cond_broadcast(&data.queue_cond);
    pthread_mutex_unlock(&data.queue_mutex);

    for (int i = 0; i < thread_count; i++) {
        pthread_join(threads[i], nullptr);
    }

    pthread_mutex_destroy(&data.queue_mutex);
    pthread_mutex_destroy(&data.image_mutex);
    pthread_cond_destroy(&data.queue_cond);

    dlclose(handle);

    std::cout << "Done: " << data.added << " added, "
              << data.errors << " errors\n";
    return data.errors == 0;
}

static int compare_records(const void *a, const void *b) {
    const std::pair<std::string, uint32_t> *pa = (const std::pair<std::string, uint32_t>*)a;
    const std::pair<std::string, uint32_t> *pb = (const std::pair<std::string, uint32_t>*)b;
    return pa->first.compare(pb->first);
}

static bool do_list(Args &args) {
    std::ifstream img(args.image, std::ios::binary);
    if (!img) {
        std::cerr << "Error: cannot open image " << args.image << "\n";
        return false;
    }

    std::vector<std::pair<std::string, uint32_t>> entries;

    while (true) {
        std::string name;
        std::vector<unsigned char> salt, content;
        if (!read_record(img, name, salt, content)) break;
        entries.push_back({name, (uint32_t)content.size()});
    }

    img.close();

    if (entries.empty()) {
        std::cout << "(empty image)\n";
        return true;
    }

    std::sort(entries.begin(), entries.end(),
              [](const auto &a, const auto &b) { return a.first < b.first; });

    std::cout << "Files in image:\n";
    for (const auto &e : entries) {
        std::cout << "  " << e.first << "  " << e.second << " bytes\n";
    }

    return true;
}

static bool do_get(Args &args) {
    std::ifstream img(args.image, std::ios::binary);
    if (!img) {
        std::cerr << "Error: cannot open image " << args.image << "\n";
        return false;
    }

    // Find file in image
    std::string found_name;
    std::vector<unsigned char> found_salt, found_content;

    while (true) {
        std::string name;
        std::vector<unsigned char> salt, content;
        if (!read_record(img, name, salt, content)) break;
        if (name == args.get_filename) {
            found_name = name;
            found_salt = std::move(salt);
            found_content = std::move(content);
            break;
        }
    }
    img.close();

    if (found_name.empty()) {
        std::cerr << "Error: file '" << args.get_filename << "' not found in image\n";
        return false;
    }

    // Decrypt
    void *handle = dlopen(LIB_PATH, RTLD_NOW);
    if (!handle) {
        std::cerr << "Error: " << dlerror() << "\n";
        return false;
    }

    auto set_master_key = (set_master_key_func_t)dlsym(handle, "set_master_key");
    auto rc4_encrypt = (rc4_encrypt_func_t)dlsym(handle, "rc4_encrypt");
    if (!set_master_key || !rc4_encrypt) {
        std::cerr << "Error: symbols not found\n";
        dlclose(handle);
        return false;
    }

    // RC4 decrypt is same as encrypt (XOR with same keystream)
    set_master_key((const unsigned char*)args.key.data(), (int)args.key.size());
    rc4_encrypt(found_content.data(), (int)found_content.size(),
                found_salt.data(), SALT_SIZE);

    dlclose(handle);

    // Write output
    std::ofstream out(args.out, std::ios::binary);
    if (!out) {
        std::cerr << "Error: cannot create " << args.out << "\n";
        return false;
    }
    out.write((const char*)found_content.data(), found_content.size());
    out.close();

    std::cout << "Extracted " << found_name << " (" << found_content.size()
              << " bytes) -> " << args.out << "\n";
    return true;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        std::cerr << "Usage:\n"
                  << "  " << argv[0] << " -add -key \"secret\" -image disk.img file1 [file2...]\n"
                  << "  " << argv[0] << " -list -image disk.img\n"
                  << "  " << argv[0] << " -get -image disk.img -key \"secret\" -out file file_name\n";
        return 1;
    }

    Args args;
    int i = 1;

    if (std::string(argv[i]) == "-add") {
        args.add = true;
        i++;
    } else if (std::string(argv[i]) == "-list") {
        args.list = true;
        i++;
    } else if (std::string(argv[i]) == "-get") {
        args.get = true;
        i++;
    } else {
        std::cerr << "Error: unknown command '" << argv[i] << "'\n";
        return 1;
    }

    while (i < argc) {
        std::string arg = argv[i];
        if (arg == "-key" && i + 1 < argc) {
            args.key = argv[++i];
        } else if (arg == "-image" && i + 1 < argc) {
            args.image = argv[++i];
        } else if (arg == "-out" && i + 1 < argc) {
            args.out = argv[++i];
        } else {
            break;
        }
        i++;
    }

    if (args.image.empty()) {
        std::cerr << "Error: -image is required\n";
        return 1;
    }

    if (args.add) {
        if (args.key.empty()) {
            std::cerr << "Error: -key is required for -add\n";
            return 1;
        }
        for (; i < argc; i++)
            args.paths.push_back(argv[i]);
        if (args.paths.empty()) {
            std::cerr << "Error: no files to add\n";
            return 1;
        }
        return do_add(args) ? 0 : 1;
    }

    if (args.list) {
        return do_list(args) ? 0 : 1;
    }

    if (args.get) {
        if (args.key.empty()) {
            std::cerr << "Error: -key is required for -get\n";
            return 1;
        }
        if (args.out.empty()) {
            std::cerr << "Error: -out is required for -get\n";
            return 1;
        }
        if (i >= argc) {
            std::cerr << "Error: file_name is required for -get\n";
            return 1;
        }
        args.get_filename = argv[i];
        return do_get(args) ? 0 : 1;
    }

    std::cerr << "Error: no command specified\n";
    return 1;
}
