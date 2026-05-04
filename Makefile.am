SUBDIRS = . test

# 1. Build the server executable
bin_PROGRAMS = abiaudit

abiaudit_SOURCES = abiaudit.cpp
abiaudit_CXXFLAGS = $(ABIGAIL_CFLAGS)
# Note: -lelf is automatically handled by the AC_CHECK_LIB macro in configure.ac,
# but we add ABIGAIL_LIBS derived from pkg-config.
abiaudit_LDADD = $(ABIGAIL_LIBS)

# 2. Build the client LD_AUDIT library
lib_LTLIBRARIES = libabiaudit.la

libabiaudit_la_SOURCES = libabiaudit.cpp
libabiaudit_la_CXXFLAGS = $(ABIGAIL_CFLAGS)
libabiaudit_la_LIBADD = -ldl
# -module: Builds a dynamically loadable module (plugin).
# -avoid-version: Prevents appending version numbers (so it creates libabiaudit.so).
libabiaudit_la_LDFLAGS = -module -avoid-version -shared

# 3. Extra files to include in the distribution tarball (make dist)
EXTRA_DIST = README.md autogen.sh

# 4. Extra files to remove during 'make clean'
CLEANFILES = *.dwo *~
