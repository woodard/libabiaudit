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

// Global IPC and Namespace state
static std::mutex g_ipc_mutex;
static std::mutex g_namespace_mutex;
static int g_sock = -1;

static std::unordered_map<uintptr_t*, Lmid_t> g_namespace_map;

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
            if (strstr(search_name, audit_target_name) != nullptr) {
                return true;
            }
        }
    }
    return false;
}

extern "C" {

unsigned int la_version(unsigned int version) {
    if (version == 0) return 0;

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
    if (access(name, R_OK) != 0) {
        return const_cast<char*>(name);
    }

    Lmid_t target_lmid = LM_ID_BASE; 

    {
        std::lock_guard<std::mutex> lock(g_namespace_mutex);
        if (g_namespace_map.count(cookie)) {
            target_lmid = g_namespace_map[cookie];
        }
    }

    if (is_loaded_as_audit(cookie, name)) {
        target_lmid = LM_ID_NEWLM;
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
        return LA_FLG_BINDTO | LA_FLG_BINDFROM;
    }

    {
        std::lock_guard<std::mutex> lock(g_namespace_mutex);
        g_namespace_map[cookie] = lmid;
    }

    std::string path = map->l_name;
    
    std::string resp = send_cmd("LOAD " + path);
    if (resp == "OK") {
        // Pass LMID, the Cookie pointer as an ID, and the path
        send_cmd("COMMIT " + std::to_string(lmid) + " " + 
                 std::to_string(reinterpret_cast<uintptr_t>(cookie)) + " " + path);
    }

    return LA_FLG_BINDTO | LA_FLG_BINDFROM;
}

unsigned int la_objclose(uintptr_t* cookie) {
    if (g_sock >= 0) {
        send_cmd("DELETE_COOKIE " + std::to_string(reinterpret_cast<uintptr_t>(cookie)));
    }
    return 0; // Return value is ignored by glibc
}

void la_preinit([[maybe_unused]] uintptr_t* cookie) {
    if (g_sock >= 0) {
        std::string resp = send_cmd("PREINIT");
        if (resp == "QUIT") {
            // No dlopen detected, we are done. Shut down the socket.
            close(g_sock);
            g_sock = -1;
        }
        // If "CONTINUE", g_sock remains open to audit runtime dlopen()s
    }
}

} // extern "C"
