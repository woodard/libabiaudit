AC_PREREQ([2.69])
AC_INIT([abiaudit], [0.1], [your_email@example.com])

# Use 'foreign' to avoid requiring strict GNU files like NEWS, AUTHORS, or ChangeLog
AM_INIT_AUTOMAKE([foreign subdir-objects])

# Initialize libtool (required for building shared libraries)
LT_INIT

# Check for C++ compiler
AC_PROG_CXX

# Set required compiler flags (C++17, warnings, and split-dwarf for debugging)
CXXFLAGS="$CXXFLAGS -std=c++17 -Wall -Wextra -g -gsplit-dwarf"

# Check for pkg-config (required to find libabigail)
PKG_PROG_PKG_CONFIG

# Check for libabigail
PKG_CHECK_MODULES([ABIGAIL], [libabigail], [], [
    AC_MSG_ERROR([libabigail is required but could not be found via pkg-config.])
])

# Check for libelf
AC_CHECK_LIB([elf], [elf_version], [], [
    AC_MSG_ERROR([libelf is required but could not be found.])
])

AC_CONFIG_FILES([Makefile test/Makefile])
AC_OUTPUT
