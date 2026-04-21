# Compiler settings
CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -O2 -g -gsplit-dwarf -I/usr/include/libabigail

# Server settings
SERVER_TARGET = abiaudit
SERVER_LDLIBS = -labigail

# Client settings
CLIENT_TARGET = libabiaudit.so
CLIENT_LDFLAGS = -shared
CLIENT_LDLIBS = -ldl

# Default target
all: $(SERVER_TARGET) $(CLIENT_TARGET)

# Rule to build the Server Application
$(SERVER_TARGET): abiaudit.cpp
	$(CXX) $(CXXFLAGS) -o $@ $^ $(SERVER_LDLIBS)

# Rule to build the Client LD_AUDIT Library
$(CLIENT_TARGET): libabiaudit.cpp
	$(CXX) $(CXXFLAGS) -fPIC $(CLIENT_LDFLAGS) -o $@ $^ $(CLIENT_LDLIBS)

# Clean up build artifacts and editor backups
clean:
	rm -f $(SERVER_TARGET) $(CLIENT_TARGET) *.o *.dwo *~

.PHONY: all clean
