#!/bin/sh
# This script generates the configure script and Makefile.in templates.
set -e

echo "Bootstrapping Autotools environment..."
autoreconf --install --force --verbose
echo "Done! You can now run ./configure"
