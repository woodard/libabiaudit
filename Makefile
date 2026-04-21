# Compiler settings
CXX = g++
CXXFLAGS = -gsplit-dwarf -std=c++17 -fPIC -Wall -Wextra -O2 -I/usr/include/libabigail

# Linker settings
LDFLAGS = -shared
LDLIBS = -labigail -ldl

# Target and source files
TARGET = libabiaudit.so
SRCS = libabiaudit.cpp
OBJS = $(SRCS:.cpp=.o)

# Default target
all: $(TARGET)

# Rule to link the shared library
$(TARGET): $(OBJS)
	$(CXX) $(LDFLAGS) -o $@ $^ $(LDLIBS)

# Rule to compile C++ source files into object files
%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Clean up build artifacts
clean:
	rm -f $(OBJS) $(TARGET)

# Phony targets to prevent conflicts with files named 'all' or 'clean'
.PHONY: all clean
