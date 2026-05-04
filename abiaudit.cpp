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
#include <fcntl.h>
#include <link.h>

// elfutils headers for .dynsym parsing
#include <libelf.h>
#include <gelf.h>

// libabigail headers
#include <abg-corpus.h>
#include <abg-reader.h>
#include <abg-dwarf-reader.h>
#include <abg-comparison.h>

static bool is_abi_compatible(const abigail::corpus_sptr& obj1, 
                              const abigail::corpus_sptr& obj2,
                              bool verbose_mode) {
    if (!obj1 || !obj2) return true;

    abigail::comparison::diff_context_sptr diff_ctxt(new abigail::comparison::diff_context());
    
    // Mimic abicompat's default output formatting settings
    diff_ctxt->show_added_fns(false);
    diff_ctxt->show_added_vars(false);
    diff_ctxt->show_linkage_names(true);
    diff_ctxt->show_locs(true);
    
    diff_ctxt->switch_categories_off(
        abigail::comparison::get_default_harmless_categories_bitmap()
    );

    abigail::comparison::corpus_diff_sptr diff = 
        abigail::comparison::compute_diff(obj1, obj2, diff_ctxt);

    if (!diff) return true;
    
    bool is_incompatible = diff->has_incompatible_changes();

    // If verbose mode is on and we found a break, print it using abicompat's format
    if (is_incompatible && verbose_mode) {
        std::cerr << "ELF file '" << obj2->get_path() 
                  << "' is not ABI compatible with '" << obj1->get_path() 
                  << "' due to differences below:\n";
        
        // This generates the standard libabigail diff tree report
        diff->report(std::cerr);
        std::cerr << "\n";
    }

    return !is_incompatible;
}

// Scans the .dynsym section of an ELF file for "dlopen" or "dlmopen"
static bool check_for_dlopen(const std::string& path) {
    int fd = open(path.c_str(), O_RDONLY);
    if (fd < 0) return false;
    
    if (elf_version(EV_CURRENT) == EV_NONE) {
        close(fd);
        return false;
    }

    Elf* elf = elf_begin(fd, ELF_C_READ, nullptr);
    if (!elf) {
        close(fd);
        return false;
    }

    bool found = false;
    Elf_Scn* scn = nullptr;
    GElf_Shdr shdr;

    while ((scn = elf_nextscn(elf, scn)) != nullptr) {
        if (gelf_getshdr(scn, &shdr) != &shdr) continue;
        
        if (shdr.sh_type == SHT_DYNSYM) {
            Elf_Data* data = elf_getdata(scn, nullptr);
            int count = shdr.sh_size / shdr.sh_entsize;
            
            for (int i = 0; i < count; ++i) {
                GElf_Sym sym;
                gelf_getsym(data, i, &sym);
                const char* name = elf_strptr(elf, shdr.sh_link, sym.st_name);
                
                if (name && (strcmp(name, "dlopen") == 0 || strcmp(name, "dlmopen") == 0)) {
                    found = true;
                    break;
                }
            }
        }
        if (found) break;
    }

    elf_end(elf);
    close(fd);
    return found;
}

int main(int argc, char** argv) {
    bool verbose_mode = false;
    int opt;

    // Parse command line arguments
    while ((opt = getopt(argc, argv, "v")) != -1) {
        switch (opt) {
            case 'v':
                verbose_mode = true;
                break;
            default:
                std::cerr << "Usage: " << argv[0] << " [-v] <target_program> [args...]\n";
                return 1;
        }
    }

    // Ensure a target program was provided after the options
    if (optind >= argc) {
        std::cerr << "Usage: " << argv[0] << " [-v] <target_program> [args...]\n";
        return 1;
    }

    int server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket");
        return 1;
    }

    struct sockaddr_un addr;
    addr.sun_family = AF_UNIX;
    std::string sock_path = "/tmp/abiaudit." + std::to_string(getpid()) + ".sock";
    strncpy(addr.sun_path, sock_path.c_str(), sizeof(addr.sun_path) - 1);

    unlink(sock_path.c_str()); 
    if (bind(server_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind");
        return 1;
    }
    
    if (listen(server_fd, 1) < 0) {
        perror("listen");
        return 1;
    }

    setenv("ABIAUDIT_SOCKET", sock_path.c_str(), 1);

    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return 1;
    }

    if (pid == 0) {
        setenv("LD_AUDIT", "./libabiaudit.so", 1); 
        execvp(argv[optind], &argv[optind]);
        perror("execvp");
        exit(1);
    }

    int client_fd = accept(server_fd, nullptr, nullptr);
    if (client_fd < 0) {
        perror("accept");
        unlink(sock_path.c_str());
        return 1;
    }

    FILE* stream = fdopen(client_fd, "r+");
    setvbuf(stream, nullptr, _IOLBF, 0);

    abigail::ir::environment env;
    std::unordered_map<std::string, abigail::corpus_sptr> corpora;
    std::unordered_map<Lmid_t, std::vector<std::string>> loaded_lists;
    
    // Track cookie -> {lmid, path} for la_objclose tracking
    std::unordered_map<uintptr_t, std::pair<Lmid_t, std::string>> cookie_map;

    bool uses_dlopen = false;
    bool wait_for_child = true;

    char line[4096];
    while (fgets(line, sizeof(line), stream)) {
        std::string req(line);
        if (!req.empty() && req.back() == '\n') req.pop_back();

        if (verbose_mode) {
            std::cerr << "[SERVER] Received command: " << req << "\n";
        }

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
        else if (cmd == "CHECK") {
            size_t sep = args.find(' ');
            Lmid_t lmid = std::stoll(args.substr(0, sep));
            std::string path = args.substr(sep + 1);
            
            if (lmid == LM_ID_NEWLM) {
                fprintf(stream, "COMPATIBLE\n");
            } else {
                bool compatible = true;
                if (corpora.count(path)) {
                    auto candidate = corpora[path];
                    for (const auto& loaded_path : loaded_lists[lmid]) {
                        if (loaded_path == path) continue;
                        auto loaded = corpora[loaded_path];
                        
                        if (!is_abi_compatible(loaded, candidate, verbose_mode) || 
                            !is_abi_compatible(candidate, loaded, verbose_mode)) {
                            compatible = false;
                            break;
                        }
                    }
                } else {
                    compatible = false;
                }
                fprintf(stream, compatible ? "COMPATIBLE\n" : "INCOMPATIBLE\n");
            }
        } 
        else if (cmd == "COMMIT") {
            size_t sep1 = args.find(' ');
            size_t sep2 = args.find(' ', sep1 + 1);
            
            Lmid_t lmid = std::stoll(args.substr(0, sep1));
            uintptr_t cookie = std::stoull(args.substr(sep1 + 1, sep2 - sep1 - 1));
            std::string path = args.substr(sep2 + 1);
            
            auto& list = loaded_lists[lmid];
            if (std::find(list.begin(), list.end(), path) == list.end()) {
                list.push_back(path);
            }
            cookie_map[cookie] = {lmid, path};

            if (!uses_dlopen && check_for_dlopen(path)) {
                uses_dlopen = true;
            }

            fprintf(stream, "OK\n");
        } 
        else if (cmd == "DELETE_COOKIE") { 
            uintptr_t cookie = std::stoull(args);
            if (cookie_map.count(cookie)) {
                Lmid_t lmid = cookie_map[cookie].first;
                std::string path = cookie_map[cookie].second;
                
                auto& list = loaded_lists[lmid];
                list.erase(std::remove(list.begin(), list.end(), path), list.end());
                cookie_map.erase(cookie);
            }
            fprintf(stream, "OK\n");
        }
        else if (cmd == "DELETE_PATH") { 
            corpora.erase(args);
            fprintf(stream, "OK\n");
        }
        else if (cmd == "PREINIT") {
            if (uses_dlopen) {
                fprintf(stream, "CONTINUE\n");
            } else {
                fprintf(stream, "QUIT\n");
                wait_for_child = false; 
                break;
            }
        }
        else if (cmd == "QUIT") {
            break;
        }
        fflush(stream);
    }

    fclose(stream);
    close(server_fd);
    unlink(sock_path.c_str());

    if (wait_for_child) {
        waitpid(pid, nullptr, 0);
    }

    return 0;
}
