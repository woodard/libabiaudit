#!/bin/sh
ln -sf ../.libs/libabiaudit.so ./libabiaudit.so 2>/dev/null || ln -sf ../libabiaudit.so .

cat << 'EOF' > rev_main.cpp
extern "C" void call_a();
int main() { call_a(); return 0; }
EOF

cat << 'EOF' > rev_lib_a_v1.cpp
struct Context { int x; };
extern "C" void call_b();
extern "C" void call_a() { call_b(); }
extern "C" void callback_from_b(Context* c) {}
EOF

cat << 'EOF' > rev_lib_a_v2.cpp
struct Context { int x; int y; }; // Context structurally changed!
extern "C" void call_b();
extern "C" void call_a() { call_b(); }
extern "C" void callback_from_b(Context* c) {}
EOF

cat << 'EOF' > rev_lib_b.cpp
struct Context { int x; };
extern "C" void callback_from_b(Context* c);
extern "C" void call_b() { Context c; callback_from_b(&c); }
EOF

g++ -g -shared -fPIC -o libb.so rev_lib_b.cpp
g++ -g -shared -fPIC -o liba.so rev_lib_a_v1.cpp -L. -lb -Wl,-rpath=.
g++ -g -o rev_test rev_main.cpp -L. -la -Wl,-rpath=.

# Overwrite libA with v2. LibB's expectation of LibA is now broken.
g++ -g -shared -fPIC -o liba.so rev_lib_a_v2.cpp -L. -lb -Wl,-rpath=.

../abiaudit ./rev_test
if [ $? -ne 0 ]; then
    exit 0 # Success: Tool caught the reverse-dependency mismatch
else
    exit 1 # Failure
fi
