#!/bin/sh
ln -sf ../.libs/libabiaudit.so ./libabiaudit.so 2>/dev/null || ln -sf ../libabiaudit.so .

../abiaudit /usr/bin/true || exit 1
../abiaudit /bin/ls > /dev/null || exit 1
exit 0
