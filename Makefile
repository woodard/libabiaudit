# Project Version
VERSION = 0.1

# Compiler settings
CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -O2 -g -gsplit-dwarf -I/usr/include/libabigail

# Server settings
SERVER_TARGET = abiaudit
SERVER_LDLIBS = -labigail -lelf

# Client settings
CLIENT_TARGET = libabiaudit.so
CLIENT_LDFLAGS = -shared
CLIENT_LDLIBS = -ldl

# Distribution settings
DIST_FILES = abiaudit.cpp libabiaudit.cpp Makefile README.md
DIST_ARCHIVE = abiaudit-$(VERSION).tar.gz

# Default target
all: $(SERVER_TARGET) $(CLIENT_TARGET)

# Rule to build the Server Application
$(SERVER_TARGET): abiaudit.cpp
	$(CXX) $(CXXFLAGS) -o $@ $^ $(SERVER_LDLIBS)

# Rule to build the Client LD_AUDIT Library
$(CLIENT_TARGET): libabiaudit.cpp
	$(CXX) $(CXXFLAGS) -fPIC $(CLIENT_LDFLAGS) -o $@ $^ $(CLIENT_LDLIBS)

# Create a distribution tarball
dist:
	tar -czvf $(DIST_ARCHIVE) $(DIST_FILES)

# Clean up build artifacts, editor backups, and distribution archives
clean:
	rm -f $(SERVER_TARGET) $(CLIENT_TARGET) *.o *.dwo *~ $(DIST_ARCHIVE)

.PHONY: all clean dist
