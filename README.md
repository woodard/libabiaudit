# abiaudit

**abiaudit** is a runtime ABI (Application Binary Interface)
compatibility verifier for Linux. It leverages the glibc dynamic
linker audit interface (`LD_AUDIT`) and the `libabigail` library to
ensure that shared objects loaded into a process are strictly
ABI-compatible with all previously loaded objects.

## Purpose

ABI breakages in dynamic environments can lead to undefined behavior,
memory corruption, and silent data corruption. While tools like
`abicompat` can verify ABI compatibility offline, `abiaudit` enforces
it strictly at *runtime*.

It verifies compatibility bidirectionally:
1. It ensures the newly loaded library provides the interfaces
   expected by already loaded libraries.
2. It ensures the newly loaded library's expectations are met by the
   already loaded libraries.

If an incompatibility is detected, the dynamic linker is instructed to
reject the candidate library.

## How It Works

Because the dynamic linker (`ld.so`) environment is highly sensitive
and volatile, running heavy C++ logic (like parsing DWARF debug info
into `libabigail` corpora) directly inside the linker hook can cause
deadlocks, extreme memory usage, and debugging nightmares.

To solve this, `abiaudit` uses a robust **Client/Server architecture**
communicating over a Unix Domain Socket.

### 1. The Server (`abiaudit` launcher)
The server acts as both the launcher for the target application and
the ABI analysis engine.
* It sets up a Unix Domain Socket and exports its path via the
  `ABIAUDIT_SOCKET` environment variable.
* It injects the client hook into the target application by setting
  `LD_AUDIT=./libabiaudit.so` specifically for the child process.
* It answers IPC requests from the client to load ELF/DWARF corpora,
  group them by linker namespaces (`Lmid_t`), and perform heavy
  bidirectional ABI comparisons.
* **Optimization:** Upon committing a new library to a namespace, it
  uses `libelf` to scan the library's `.dynsym` section for `dlopen`
  or `dlmopen`. Once the dynamic linker finishes initial process setup
  (`la_preinit`), the server checks if any loaded libraries actually
  have the capability to load more code dynamically. If not, the
  server safely drops the socket and exits, reparenting the child
  process to `init` and removing all audit overhead for the rest of
  the runtime.

### 2. The Client (`libabiaudit.so`)
The client is a highly optimized, lightweight shared library loaded
directly by the dynamic linker.
* **`la_objsearch`**: Intercepts library resolution. It asks the
  server to check the candidate library against the target
  namespace. If the server replies `INCOMPATIBLE`, it returns `NULL`
  to force the linker to reject the path.
* **Namespace Tracking**: Objects loaded via `DT_AUDIT` are strictly
  isolated. Objects loaded via standard dependencies inherit the
  namespace of the object requesting them (tracked via the `cookie`
  pointer).
* **`dlmopen` Interception**: To accurately track custom namespaces
  requested via `dlmopen` (which is normally hidden from
  `la_objsearch`), the client selectively requests symbol binding
  (`la_symbind64`) only for `libdl.so` and `libc.so`. It dynamically
  wraps the PLT resolution of `dlmopen` to capture the requested
  `Lmid_t` and route it to the correct namespace check.
* **`la_objclose`**: Notifies the server when libraries are unloaded
  so their corpora can be freed.

## Prerequisites

You need a C++17 compiler and the development headers for `libabigail`
and `libelf`.
