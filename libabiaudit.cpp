#include <link.h>
#include <unistd.h>
#include <iostream>
#include <string>
#include <vector>
#include <mutex>
#include <sys/socket.h>
#include <sys/un.h>
#include <cstdlib>

// Global IPC state
static std::mutex g_ipc_mutex;
static int g_sock = -1;
static bool g_init_complete = false;

// Basic function to read a single newline-delimited string
static std::string read_line() {
    std::string resp;
    char c;
    while (read(g_sock, &c, 1) == 1) {
        if (c == '\n') break;
        resp += c;
    }
    return resp;
}

// Function to send a command and receive a single-line response
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

// Function to fetch the dynamic list of loaded libraries
static std::vector<std::string> get_loaded_list() {
    std::lock_guard<std::mutex> lock(g_ipc_mutex);
    std::vector<std::string> list;
    if (g_sock < 0) return list;

    std::string to_send = "LIST\n";
    if (write(g_sock, to_send.c_str(), to_send.size()) < 0) return list;

    std::string start = read_line();
    if (start != "LIST_START") return list;

    while (true) {
        std::string line = read_line();
        if (line == "LIST_END" || line.empty()) break;
        list.push_back(line);
    }
    return list;
}

extern "C" {

unsigned int la_version(unsigned int version) {
    if (version == 0) return 0;

    // Connect to the server defined by the launcher
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

char* la_objsearch(const char* name, [[maybe_unused]] uintptr_t* cookie, [[maybe_unused]] unsigned int flag) {
    if (!name || name[0] == '\0' || g_init_complete || g_sock < 0) {
        return const_cast<char*>(name);
    }
    if (access(name, R_OK) != 0) {
        return const_cast<char*>(name);
    }

    std::string path = name;
    
    // 1. Ask Server to load the ABI
    std::string resp = send_cmd("LOAD " + path);
    if (resp != "OK") return nullptr; // Parse failed

    // 2. Fetch previously loaded ABIs from Server
    std::vector<std::string> loaded_libs = get_loaded_list();

    // 3. Command Server to compare candidate against every loaded ABI bi-directionally
    for (const auto& loaded_lib : loaded_libs) {
        if (loaded_lib == path) continue;

        std::string c1 = send_cmd("COMPARE " + loaded_lib + " " + path);
        std::string c2 = send_cmd("COMPARE " + path + " " + loaded_lib);

        if (c1 != "COMPATIBLE" || c2 != "COMPATIBLE") {
            std::cerr << "[LD_AUDIT] ABI Incompatibility between '" << loaded_lib 
                      << "' and '" << path << "'\n";
            
            // Delete the incompatible candidate corpus to free memory
            send_cmd("DELETE " + path);
            return nullptr;
        }
    }

    return const_cast<char*>(name);
}

unsigned int la_objopen(struct link_map* map, [[maybe_unused]] Lmid_t lmid, [[maybe_unused]] uintptr_t* cookie) {
    if (g_init_complete || !map || !map->l_name || map->l_name[0] == '\0' || g_sock < 0) {
        return LA_FLG_BINDTO | LA_FLG_BINDFROM;
    }

    std::string path = map->l_name;
    
    // Ensure the server has it loaded (e.g., if la_objsearch was bypassed)
    std::string resp = send_cmd("LOAD " + path);
    if (resp == "OK") {
        // Promote it to the official comparison list
        send_cmd("COMMIT " + path);
    }

    return LA_FLG_BINDTO | LA_FLG_BINDFROM;
}

void la_preinit([[maybe_unused]] uintptr_t* cookie) {
    g_init_complete = true;
    if (g_sock >= 0) {
        std::vector<std::string> loaded_libs = get_loaded_list();
        for (const auto& l : loaded_libs) {
            send_cmd("DELETE " + l);
        }
        send_cmd("QUIT");
        close(g_sock);
        g_sock = -1;
    }
}

} // extern "C"
