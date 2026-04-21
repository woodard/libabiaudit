#include <iostream>
#include <string>
#include <unordered_map>
#include <vector>
#include <algorithm>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <sys/wait.h>
#include <cstdlib>
#include <cstdio>
#include <cstring>

// libabigail headers
#include <abg-corpus.h>
#include <abg-reader.h>
#include <abg-dwarf-reader.h>
#include <abg-comparison.h>

static bool is_abi_compatible(const abigail::corpus_sptr& obj1, 
                              const abigail::corpus_sptr& obj2) {
    if (!obj1 || !obj2) return true;

    abigail::comparison::diff_context_sptr diff_ctxt(new abigail::comparison::diff_context());
    diff_ctxt->switch_categories_off(
        abigail::comparison::get_default_harmless_categories_bitmap()
    );

    abigail::comparison::corpus_diff_sptr diff = 
        abigail::comparison::compute_diff(obj1, obj2, diff_ctxt);

    if (!diff) return true;
    return !diff->has_incompatible_changes();
}

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <target_program> [args...]\n";
        return 1;
    }

    // 1. Create a Unix Domain Socket
    int server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket");
        return 1;
    }

    struct sockaddr_un addr;
    addr.sun_family = AF_UNIX;
    std::string sock_path = "/tmp/abiaudit." + std::to_string(getpid()) + ".sock";
    strncpy(addr.sun_path, sock_path.c_str(), sizeof(addr.sun_path) - 1);

    unlink(sock_path.c_str()); // Ensure clean state
    if (bind(server_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind");
        return 1;
    }
    
    if (listen(server_fd, 1) < 0) {
        perror("listen");
        return 1;
    }

    // 2. Set the socket environment variable (inherited by the child)
    setenv("ABIAUDIT_SOCKET", sock_path.c_str(), 1);

    // 3. Fork and launch target program
    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return 1;
    }

    if (pid == 0) {
        // Child Process: Launch the target application
        
        // Set LD_AUDIT exclusively for the child process so the parent remains clean.
        // Assumes libabiaudit.so is built in the current directory, or in the library path.
        setenv("LD_AUDIT", "./libabiaudit.so", 1); 
        
        execvp(argv[1], &argv[1]);
        perror("execvp");
        exit(1);
    }

    // 4. Parent Process: Server Loop
    int client_fd = accept(server_fd, nullptr, nullptr);
    if (client_fd < 0) {
        perror("accept");
        unlink(sock_path.c_str());
        return 1;
    }

    FILE* stream = fdopen(client_fd, "r+");
    setvbuf(stream, nullptr, _IOLBF, 0); // Line buffering

    abigail::ir::environment env;
    std::unordered_map<std::string, abigail::corpus_sptr> corpora;
    std::vector<std::string> loaded_list;

    char line[4096];
    while (fgets(line, sizeof(line), stream)) {
        std::string req(line);
        if (!req.empty() && req.back() == '\n') req.pop_back();

        size_t first_space = req.find(' ');
        std::string cmd = req.substr(0, first_space);
        std::string args = (first_space != std::string::npos) ? req.substr(first_space + 1) : "";

        if (cmd == "LOAD") {
            if (corpora.find(args) != corpora.end()) {
                fprintf(stream, "OK\n");
            } else {
                std::vector<std::string> di_roots;
                abigail::fe_iface::status status = abigail::fe_iface::STATUS_UNKNOWN;
                auto corpus = abigail::dwarf::read_corpus_from_elf(args, di_roots, env, false, status);
                if (corpus) {
                    corpora[args] = corpus;
                    fprintf(stream, "OK\n");
                } else {
                    fprintf(stream, "FAIL\n");
                }
            }
        } 
        else if (cmd == "COMPARE") {
            size_t sep = args.find(' ');
            std::string p1 = args.substr(0, sep);
            std::string p2 = args.substr(sep + 1);
            
            if (corpora.count(p1) && corpora.count(p2)) {
                if (is_abi_compatible(corpora[p1], corpora[p2])) {
                    fprintf(stream, "COMPATIBLE\n");
                } else {
                    fprintf(stream, "INCOMPATIBLE\n");
                }
            } else {
                fprintf(stream, "ERROR\n");
            }
        } 
        else if (cmd == "COMMIT") {
            // Promotes a loaded corpus to the official "loaded list" for comparison
            if (std::find(loaded_list.begin(), loaded_list.end(), args) == loaded_list.end()) {
                loaded_list.push_back(args);
            }
            fprintf(stream, "OK\n");
        } 
        else if (cmd == "DELETE") {
            corpora.erase(args);
            loaded_list.erase(std::remove(loaded_list.begin(), loaded_list.end(), args), loaded_list.end());
            fprintf(stream, "OK\n");
        } 
        else if (cmd == "LIST") {
            fprintf(stream, "LIST_START\n");
            for (const auto& l : loaded_list) {
                fprintf(stream, "%s\n", l.c_str());
            }
            fprintf(stream, "LIST_END\n");
        } 
        else if (cmd == "QUIT") {
            break;
        }
        fflush(stream);
    }

    // Cleanup
    fclose(stream);
    close(server_fd);
    unlink(sock_path.c_str());
    waitpid(pid, nullptr, 0);

    return 0;
}
