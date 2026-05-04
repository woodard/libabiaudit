#!/bin/sh
ln -sf ../.libs/libabiaudit.so ./libabiaudit.so 2>/dev/null || ln -sf ../libabiaudit.so .

cat << 'EOF' > harmless_main.cpp
extern "C" void used_func();
int main() { used_func(); return 0; }
EOF

cat << 'EOF' > harmless_lib_v1.cpp
extern "C" void used_func() {}
extern "C" void unused_func(int) {}
EOF

cat << 'EOF' > harmless_lib_v2.cpp
extern "C" void used_func() {}
extern "C" void unused_func(double, int) {} // ABI changed, but harmless!
EOF

g++ -g -shared -fPIC -o libharmless.so harmless_lib_v1.cpp
g++ -g -o harmless_test harmless_main.cpp -L. -lharmless -Wl,-rpath=.

# Overwrite with V2. test should PASS because used_func is intact.
g++ -g -shared -fPIC -o libharmless.so harmless_lib_v2.cpp

../abiaudit ./harmless_test || exit 1
exit 0
