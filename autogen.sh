#!/bin/sh
#
# autogen.sh - Bootstraps the Autotools environment and optionally runs configure.
#

# Exit immediately if any command fails
set -e

# Change to the directory where the script is located, 
# ensuring it works even if called from outside the project root.
cd "$(dirname "$0")"

echo "Bootstrapping the Autotools build system..."
# -v: verbose
# -f: force re-generation of all files
# -i: install missing auxiliary files (like install-sh, missing, depcomp)
autoreconf -vfi

# If NOCONFIGURE is set, stop here.
if test -n "$NOCONFIGURE"; then
    echo "================================================================="
    echo " Autotools generation complete."
    echo " Skipping ./configure step because NOCONFIGURE is set."
    echo " You can run it manually whenever you are ready: ./configure"
    echo "================================================================="
    exit 0
fi

echo "================================================================="
echo " Autotools generation complete. Running ./configure..."
echo "================================================================="

# Execute configure, passing along any arguments provided to this script
exec ./configure "$@"
