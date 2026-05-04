#!/bin/sh
ln -sf ../.libs/libabiaudit.so ./libabiaudit.so 2>/dev/null || ln -sf ../libabiaudit.so .

cat << 'EOF' > mismatch_main.cpp
struct Data { int a; };
extern "C" void process(Data* d);
int main() { Data d; process(&d); return 0; }
EOF

cat << 'EOF' > mismatch_lib_v1.cpp
struct Data { int a; };
extern "C" void process(Data* d) {}
EOF

cat << 'EOF' > mismatch_lib_v2.cpp
struct Data { int a; int b; }; // Layout changed maliciously!
extern "C" void process(Data* d) {}
EOF

g++ -g -shared -fPIC -o libmismatch.so mismatch_lib_v1.cpp
g++ -g -o mismatch_test mismatch_main.cpp -L. -lmismatch -Wl,-rpath=.

# Overwrite with v2. abiaudit MUST catch this.
g++ -g -shared -fPIC -o libmismatch.so mismatch_lib_v2.cpp

../abiaudit ./mismatch_test
if [ $? -ne 0 ]; then
    exit 0 # Success: The tool detected the mismatch and killed the process
else
    exit 1 # Failure: The tool allowed broken ABI code to execute
fi
