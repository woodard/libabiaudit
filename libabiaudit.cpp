#include <link.h>
#include <dlfcn.h>
#include <unistd.h>
#include <iostream>
#include <vector>
#include <string>
#include <mutex>
#include <unordered_map>
#include <exception>

// libabigail headers
#include <abg-corpus.h>
#include <abg-reader.h>        // Added for abigail::fe_iface::status
#include <abg-dwarf-reader.h>  // Added for abigail::dwarf::read_corpus_from_elf
#include <abg-comparison.h>

// Global state
static std::mutex g_audit_mutex;
static bool g_init_complete = false;
static abigail::ir::environment g_abg_env;

// Cache of libraries successfully loaded
static std::vector<abigail::corpus_sptr> g_loaded_corpora;

// Cache of libraries currently being evaluated (to avoid re-reading DWARF 
// between la_objsearch and la_objopen)
static std::unordered_map<std::string, abigail::corpus_sptr> g_corpus_cache;

// Helper function to check ABI compatibility
// Returns true if compatible, false if incompatible changes are detected.
static bool is_abi_compatible(const abigail::corpus_sptr& obj1, 
                              const abigail::corpus_sptr& obj2) {
    if (!obj1 || !obj2) return true; // Cannot compare, fallback to allow

    // Correctly instantiate the diff_context
    abigail::comparison::diff_context_sptr diff_ctxt(new abigail::comparison::diff_context());
    
    // Ignore harmless changes (e.g., compatible types, benign name changes) 
    // to avoid false positive rejections at runtime.
    diff_ctxt->switch_categories_off(
        abigail::comparison::get_default_harmless_categories_bitmap()
    );

    abigail::comparison::corpus_diff_sptr diff = 
        abigail::comparison::compute_diff(obj1, obj2, diff_ctxt);

    if (!diff) return true; // No differences found

    // If there are differences, we only block if they break the ABI
    return !diff->has_incompatible_changes();
}

extern "C" {

// 1. Handshake to establish LD_AUDIT version
unsigned int la_version(unsigned int version) {
    if (version == 0) return 0;
    return LAV_CURRENT;
}

// 2. Intercept library searches to perform ABI checks
char* la_objsearch(const char* name, uintptr_t* cookie, unsigned int flag) {
    if (!name || name[0] == '\0') return const_cast<char*>(name);

    std::lock_guard<std::mutex> lock(g_audit_mutex);

    // If init_complete probe is passed, skip the heavy ABI checking for late dlopen()
    if (g_init_complete) {
        return const_cast<char*>(name);
    }

    // Fast filesystem check: Skip if the file doesn't exist or isn't readable
    if (access(name, R_OK) != 0) {
        return const_cast<char*>(name);
    }

    try {
        abigail::corpus_sptr candidate_corpus;
        std::string lib_path(name);

        // Check if we already evaluated this candidate
        auto it = g_corpus_cache.find(lib_path);
        if (it != g_corpus_cache.end()) {
            candidate_corpus = it->second;
        } else {
            // Read DWARF into corpus using the correct API
            std::vector<char**> di_roots; 
            abigail::fe_iface::status status = abigail::fe_iface::STATUS_UNKNOWN;
            
            candidate_corpus = abigail::dwarf::read_corpus_from_elf(
                lib_path, di_roots, g_abg_env, false, status
            );
            
            if (candidate_corpus) {
                g_corpus_cache[lib_path] = candidate_corpus;
            }
        }

        if (candidate_corpus) {
            // Bi-directional ABI compatibility verification against all loaded objects
            for (const auto& loaded_corpus : g_loaded_corpora) {
                if (!loaded_corpus) continue;

                // Direction 1: Loaded Object -> Candidate
                if (!is_abi_compatible(loaded_corpus, candidate_corpus)) {
                    std::cerr << "[LD_AUDIT] ABI Incompatibility: Loaded '" 
                              << loaded_corpus->get_path() << "' expects interfaces missing/changed in candidate '" 
                              << lib_path << "'\n";
                    return nullptr; // Return NULL to force the linker to reject this object
                }

                // Direction 2: Candidate -> Loaded Object
                if (!is_abi_compatible(candidate_corpus, loaded_corpus)) {
                    std::cerr << "[LD_AUDIT] ABI Incompatibility: Candidate '" 
                              << lib_path << "' expects interfaces missing/changed in loaded object '" 
                              << loaded_corpus->get_path() << "'\n";
                    return nullptr; 
                }
            }
        }
    } catch (const std::exception& e) {
        std::cerr << "[LD_AUDIT] Exception evaluating " << name << ": " << e.what() << "\n";
        return nullptr;
    } catch (...) {
        std::cerr << "[LD_AUDIT] Unknown exception evaluating " << name << "\n";
        return nullptr;
    }

    // All checks passed, allow the dynamic linker to proceed with this path
    return const_cast<char*>(name);
}

// 3. Confirm object load and add to the known universe of corpora
unsigned int la_objopen(struct link_map* map, Lmid_t lmid, uintptr_t* cookie) {
    std::lock_guard<std::mutex> lock(g_audit_mutex);

    if (g_init_complete || !map || !map->l_name || map->l_name[0] == '\0') {
        return LA_FLG_BINDTO | LA_FLG_BINDFROM;
    }

    try {
        std::string lib_path(map->l_name);
        
        // If it was parsed in la_objsearch, promote it to the loaded list
        auto it = g_corpus_cache.find(lib_path);
        if (it != g_corpus_cache.end()) {
            g_loaded_corpora.push_back(it->second);
        } else if (access(lib_path.c_str(), R_OK) == 0) {
            // Main executable or vDSO edge cases that bypass la_objsearch
            std::vector<char**> di_roots;
            abigail::fe_iface::status status = abigail::fe_iface::STATUS_UNKNOWN;
            
            abigail::corpus_sptr corpus = abigail::dwarf::read_corpus_from_elf(
                lib_path, di_roots, g_abg_env, false, status
            );
            
            if (corpus) {
                g_loaded_corpora.push_back(corpus);
            }
        }
    } catch (...) {
        // Silently swallow C++ exceptions to protect the C dynamic linker
    }

    return LA_FLG_BINDTO | LA_FLG_BINDFROM;
}

// 4. Cleanup at init_complete
void la_preinit(uintptr_t* cookie) {
    std::lock_guard<std::mutex> lock(g_audit_mutex);
    
    // glibc init_complete probe point is passed
    g_init_complete = true;

    // Free the heavy libabigail corpora from memory
    g_loaded_corpora.clear();
    g_corpus_cache.clear();
}

} // extern "C"
