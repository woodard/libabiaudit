#!/bin/sh
ln -sf ../.libs/libabiaudit.so ./libabiaudit.so 2>/dev/null || ln -sf ../libabiaudit.so .

cat << 'EOF' > dl_test.cpp
#define _GNU_SOURCE
#include <dlfcn.h>
int main() {
    // Test standard dlopen
    void* h1 = dlopen("./libdl_dummy.so", RTLD_NOW);
    if (h1) dlclose(h1);
    
    // Test dlmopen into a new namespace
    void* h2 = dlmopen(LM_ID_NEWLM, "./libdl_dummy.so", RTLD_NOW);
    if (h2) dlclose(h2);
    return 0;
}
EOF

cat << 'EOF' > libdl_dummy.cpp
extern "C" void dummy() {}
EOF

g++ -g -shared -fPIC -o libdl_dummy.so libdl_dummy.cpp
g++ -g -o dl_test dl_test.cpp -ldl

../abiaudit ./dl_test || exit 1
exit 0
