#include <link.h>
#include <unistd.h>
#include <iostream>
#include <string>
#include <vector>
#include <mutex>
#include <unordered_map>
#include <sys/socket.h>
#include <sys/un.h>
#include <cstdlib>
#include <cstring>
#include <atomic>

// Global IPC and Namespace state
static std::mutex g_ipc_mutex;
static std::mutex g_namespace_mutex;
static int g_sock = -1;

static std::unordered_map<uintptr_t*, Lmid_t> g_namespace_map;
static std::unordered_map<Lmid_t, size_t> g_namespace_counts;

// Global tracking for wrappers
static thread_local bool g_dlmopen_called = false;
static thread_local Lmid_t g_dlmopen_lmid = LM_ID_BASE;
static std::atomic<void*> g_real_dlmopen{nullptr};

static bool g_exit_main = false;
static std::atomic<void*> g_real_libc_start_main{nullptr};

static std::string read_line() {
    std::string resp;
    char c;
    while (read(g_sock, &c, 1) == 1) {
        if (c == '\n') break;
        resp += c;
    }
    return resp;
}

static std::string send_cmd_locked(const std::string& cmd) {
    if (g_sock < 0) return "ERROR";
    std::string to_send = cmd + "\n";
    if (write(g_sock, to_send.c_str(), to_send.size()) < 0) {
        return "ERROR";
    }
    return read_line();
}

static std::string send_cmd(const std::string& cmd) {
    std::lock_guard<std::mutex> lock(g_ipc_mutex);
    return send_cmd_locked(cmd);
}

static bool is_ignored_library(const char* name) {
    if (!name) return false;
    if (strstr(name, "linux-vdso") != nullptr || strstr(name, "linux-gate") != nullptr) return true;
    if (strstr(name, "ld-linux") != nullptr || strstr(name, "ld.so") != nullptr) return true;
    return false;
}

static bool is_loaded_as_audit(uintptr_t* cookie, const char* search_name) {
    if (!cookie || !search_name) return false;
    struct link_map* initiating_map = reinterpret_cast<struct link_map*>(cookie);
    if (!initiating_map->l_ld) return false;

    const char* strtab = nullptr;
    for (ElfW(Dyn)* dyn = initiating_map->l_ld; dyn->d_tag != DT_NULL; ++dyn) {
        if (dyn->d_tag == DT_STRTAB) {
            strtab = reinterpret_cast<const char*>(initiating_map->l_addr + dyn->d_un.d_ptr);
            break;
        }
    }
    if (!strtab) return false;

    for (ElfW(Dyn)* dyn = initiating_map->l_ld; dyn->d_tag != DT_NULL; ++dyn) {
        if (dyn->d_tag == DT_AUDIT || dyn->d_tag == DT_DEPAUDIT) {
            const char* audit_target_name = strtab + dyn->d_un.d_val;
            if (strstr(search_name, audit_target_name) != nullptr) return true;
        }
    }
    return false;
}

extern "C" {

void* dlmopen_wrapper(Lmid_t lmid, const char* filename, int flag) {
    g_dlmopen_called = true;
    g_dlmopen_lmid = lmid;

    using dlmopen_func_t = void* (*)(Lmid_t, const char*, int);
    dlmopen_func_t real_func = reinterpret_cast<dlmopen_func_t>(g_real_dlmopen.load(std::memory_order_relaxed));

    void* result = nullptr;
    if (real_func) {
        result = real_func(lmid, filename, flag);
    }

    g_dlmopen_called = false;
    return result;
}

// The fake main function that simply exits
int fake_main([[maybe_unused]] int argc, [[maybe_unused]] char** argv, [[maybe_unused]] char** envp) {
    std::cerr << "[LD_AUDIT] The program was not run.\n";
    exit(0);
    return 0; // Unreachable
}

// Wrapper for __libc_start_main to inject the fake main
int wrapper_libc_start_main(
    [[maybe_unused]] int (*main) (int, char**, char**), 
    int argc, 
    char** ubp_av, 
    void (*init) (void), 
    void (*fini) (void), 
    void (*rtld_fini) (void), 
    void* stack_end) 
{
    std::cerr << "[LD_AUDIT] wrapper_libc_start_main called, substituting fake_main.\n";
    using libc_start_main_func_t = int (*)(int (*) (int, char**, char**), int, char**, void (*) (void), void (*) (void), void (*) (void), void*);
    libc_start_main_func_t real_func = reinterpret_cast<libc_start_main_func_t>(g_real_libc_start_main.load(std::memory_order_relaxed));
    
    // Call the real __libc_start_main, but supply our fake_main pointer
    return real_func(fake_main, argc, ubp_av, init, fini, rtld_fini, stack_end);
}

uintptr_t la_symbind64(Elf64_Sym *sym, [[maybe_unused]] unsigned int ndx,
                       [[maybe_unused]] uintptr_t *refcook, [[maybe_unused]] uintptr_t *defcook,
                       [[maybe_unused]] unsigned int *flags, const char *symname) {
    if (!symname) return sym->st_value;

    if (strcmp(symname, "dlmopen") == 0) {
        g_real_dlmopen.store(reinterpret_cast<void*>(sym->st_value), std::memory_order_relaxed);
        return reinterpret_cast<uintptr_t>(&dlmopen_wrapper);
    }
    
    if (g_exit_main && strcmp(symname, "__libc_start_main") == 0) {
        std::cerr << "[LD_AUDIT] la_symbind64 intercepted __libc_start_main symbol.\n";
        g_real_libc_start_main.store(reinterpret_cast<void*>(sym->st_value), std::memory_order_relaxed);
        return reinterpret_cast<uintptr_t>(&wrapper_libc_start_main);
    }

    return sym->st_value;
}

unsigned int la_version(unsigned int version) {
    if (version == 0) return 0;

    if (getenv("ABIAUDIT_EXIT_MAIN")) {
        g_exit_main = true;
    }

    const char* sock_path = getenv("ABIAUDIT_SOCKET");
    if (sock_path) {
        g_sock = socket(AF_UNIX, SOCK_STREAM, 0);
        if (g_sock >= 0) {
            struct sockaddr_un addr;
            addr.sun_family = AF_UNIX;
            strncpy(addr.sun_path, sock_path, sizeof(addr.sun_path) - 1);
            
            if (connect(g_sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
                close(g_sock);
                g_sock = -1;
                std::cerr << "[LD_AUDIT] Warning: Failed to connect to IPC socket.\n";
            }
        }
    }
    return LAV_CURRENT;
}

char* la_objsearch(const char* name, uintptr_t* cookie, [[maybe_unused]] unsigned int flag) {
    if (!name || name[0] == '\0' || g_sock < 0) {
        return const_cast<char*>(name);
    }
    
    if (is_ignored_library(name)) {
        return const_cast<char*>(name);
    }

    if (access(name, R_OK) != 0) {
        return const_cast<char*>(name);
    }

    Lmid_t target_lmid = LM_ID_BASE; 

    if (g_dlmopen_called) {
        target_lmid = g_dlmopen_lmid;
        g_dlmopen_called = false; 
    } else {
        std::lock_guard<std::mutex> lock(g_namespace_mutex);
        if (g_namespace_map.count(cookie)) {
            target_lmid = g_namespace_map[cookie];
        }
    }

    if (is_loaded_as_audit(cookie, name)) {
        target_lmid = LM_ID_NEWLM;
    }

    bool is_first_library = false;
    if (target_lmid == LM_ID_NEWLM) {
        is_first_library = true;
    } else {
        std::lock_guard<std::mutex> lock(g_namespace_mutex);
        if (g_namespace_counts[target_lmid] == 0) {
            is_first_library = true;
        }
    }

    if (is_first_library) {
        return const_cast<char*>(name);
    }

    std::string path = name;
    
    std::string resp = send_cmd("LOAD " + path);
    if (resp != "OK") return nullptr; 

    resp = send_cmd("CHECK " + std::to_string(target_lmid) + " " + path);

    if (resp != "COMPATIBLE") {
        std::cerr << "[LD_AUDIT] ABI Incompatibility detected for '" << path 
                  << "' in namespace " << target_lmid << "\n";
        
        send_cmd("DELETE_PATH " + path);
        return nullptr;
    }

    return const_cast<char*>(name);
}

unsigned int la_objopen(struct link_map* map, Lmid_t lmid, uintptr_t* cookie) {
    if (!map || !map->l_name || map->l_name[0] == '\0' || g_sock < 0) {
        return 0; 
    }

    if (is_ignored_library(map->l_name)) {
        return 0;
    }

    {
        std::lock_guard<std::mutex> lock(g_namespace_mutex);
        g_namespace_map[cookie] = lmid;
    }

    std::string path = map->l_name;
    
    std::string resp = send_cmd("LOAD " + path);
    if (resp == "OK") {
        send_cmd("COMMIT " + std::to_string(lmid) + " " + 
                 std::to_string(reinterpret_cast<uintptr_t>(cookie)) + " " + path);
                 
        std::lock_guard<std::mutex> lock(g_namespace_mutex);
        g_namespace_counts[lmid]++;
    }

    if (strstr(path.c_str(), "/libdl.so") != nullptr || 
        strstr(path.c_str(), "/libc.so") != nullptr ||
        strncmp(path.c_str(), "libdl.so", 8) == 0 ||
        strncmp(path.c_str(), "libc.so", 7) == 0) {
        
        return LA_FLG_BINDTO;
    }

    return 0;
}

unsigned int la_objclose(uintptr_t* cookie) {
    if (g_sock >= 0) {
        send_cmd("DELETE_COOKIE " + std::to_string(reinterpret_cast<uintptr_t>(cookie)));
        
        std::lock_guard<std::mutex> lock(g_namespace_mutex);
        if (g_namespace_map.count(cookie)) {
            Lmid_t lmid = g_namespace_map[cookie];
            if (g_namespace_counts[lmid] > 0) {
                g_namespace_counts[lmid]--;
            }
            g_namespace_map.erase(cookie);
        }
    }
    return 0; 
}

void la_preinit([[maybe_unused]] uintptr_t* cookie) {
    if (g_sock >= 0) {
        std::string resp = send_cmd("PREINIT");
        if (resp == "QUIT") {
            close(g_sock);
            g_sock = -1;
        }
    }
}

} // extern "C"
