# APOS

## Overview

APOS is an educational Unix-like monolithic kernel written largely in C. It
targets the x86, x86-64, and riscv64 architectures; boots under QEMU and on
real hardware; and exposes a POSIX-style syscall interface to userspace. The
tree includes the kernel, a small userland, an in-tree test harness, and the
build system to produce a bootable image.

APOS is licensed under the Apache-2.0 license.

## History and Purpose

I started this project in 2012 because I wanted to understand what happened in
between a power-on event and all the fancy things I studied in my OS undergrad
courses.  I then...kept on going.

Since then I have used it to learn and experiment with various domains in
systems architecture and programming.

It is written primarily for clarity and correctness, not performance.  It
supports multiple CPU architectures and includes a slim userspace and can (with
the accompanying newlib port) compile and run standard binaries like bash and
busybox.

The kernel is tested extensively (see `test` and `user-tests` directories) ---
almost half the code (by kloc) is tests (especially for the network stack).

## Features

A subset of interesting things the kernel supports:

- Kernel-mode Thread Sanitizer --- see `sanitizers/tsan/` for custom
  implementation of the TSAN algorithm and hooks into the thread and scheduler
  subsystem.
- IPv4 and IPv6 --- see `net/ip/`.
- TCP --- see `net/tcp/` (and `test/tcp_test.c`, which is ~15% of kernel code).
- NVMe
- USB

When combined with the accompanying `newlib` port, a variety of standard POSIX
software can be compiled with no or minimal changes.  `busybox` provides the
basics, and `bash` is the default shell.  I believe APOS could be fully
self-hosting, but I haven't tried yet.

## Dependencies and Building

Various other related repositories are in the
[apos-os](https://github.com/apos-os) GitHub organization, which hosts this
repository alongside the toolchain and supporting projects.

To build the kernel, you need:

- **[gn](https://gn.googlesource.com/gn/)** — the primary meta-build system.
- a cross-compiler (gcc and/or clang) for the target architecture(s).
- `ninja`
- `python3`
- `jinja2` python library (for regenerating some templated code)

For userspace binaries, you also will need to compile the APOS newlib port for
libc.

TODO(aoates): include more in-depth instructions for building a cross toolchain.

### Building the Kernel

`configure` is a script that does basic configuration of `gn`, the
meta-configuration.  It selects the active architecture and compiler --- this is
a relic of the previous build system (scons) which would only build one
architecture/compiler at once.

`build_all` is a small wrapper around `ninja` that builds the kernel after
`configure` has been run.  It can also be built directly with `ninja -C out`.

These require a short file called `build-config-system.conf` in the root of the
repository that sets system-wide configuration values.  See `./configure --help`
for more information.

Basic building example:

```
echo "CROSS_PREFIX = '/Users/$USER/cross'" > build-config-system.conf
echo "GTEST_ROOT = '/opt/homebrew/Cellar/googletest/1.17.0'" >> build-config-system.conf
./configure --arch=riscv64
./build_all
./out/native/obj/os/core/loader/gnu_hash_test
```

## Architectural Overview

APOS is a monolithic kernel with a Unix-inspired layered structure:

- **Architecture abstraction.** Architecture-specific code lives under
  `archs/<arch>/` and implements a common API defined by headers in
  `archs/common/`. Generic code includes `arch/<path>` and the build system
  resolves it to the current arch's implementation, falling back to the common
  header. See `archs/README` for the full convention.
- **Boot and kernel entry.** Per-arch boot code initializes the CPU, paging,
  and early console, then transfers to the generic kernel entry point in
  `main/kernel.c`, which brings up the rest of the subsystems in order.
- **Memory management.** A page allocator, slab/`kmalloc` allocators, a unified
  VM layer with memory objects (anon, vnode, shadow, block-device backed), and
  an `mmap` implementation live under `memory/`. Page-fault handling is
  arch-dispatched into the generic VM subsystem.
- **Processes and threading.** `proc/` contains kernel threads, processes,
  fork/exec/exit, scheduling, kernel mutexes, futexes, signals, and
  deferred-interrupt machinery.
- **VFS.** `vfs/` provides the file-system abstraction layer and concrete
  filesystems (ext2 lives under `test/ext2/` for testing; other FSes plug in
  through the VFS).
- **Devices.** `dev/` hosts drivers and device frameworks — PCI, ATA, NVMe,
  serial/UART, PS/2, keyboard, TTY/termios, ramdisk, RTC, USB, video, and a
  devicetree parser used by the riscv64 port.
- **Networking.** `net/` implements a TCP/IP stack: link layer, ARP/neighbor
  cache, IPv4/IPv6, ICMP, UDP, TCP, and BSD-style sockets.
- **Syscalls.** `syscall/` contains the syscall entry/dispatch layer, argument
  validation (the "DMZ"), and per-arch wiring; userspace reaches the kernel
  through this surface.
- **Userland.** `user/` contains the basic primitives needed to build userland
  syscall stubs and libc.  `os/` contains a larger (but still small) optional
  userspace.  `user-tests` contains userspace test binaries.

## Repository Layout

Top-level directories:

- `main/` — kernel entry point and the in-kernel shell.
- `archs/` — per-architecture code (`i586`, `x86_64`, `riscv64`, plus
  `common/` for the shared arch API and `x86-common/` for x86-shared bits).
- `common/` — utilities used everywhere: logging, assertions, strings, lists,
  hashtables, atomics, time, per-CPU data, etc.
- `memory/` — physical/virtual memory management, allocators, VM objects.
- `proc/` — processes, threads, scheduling, synchronization, signals.
- `vfs/` — virtual file system layer and core file-system support.
- `dev/` — device drivers and device subsystems.
- `net/` — networking stack (link, IP, ICMP, TCP/UDP, sockets).
- `syscall/` — syscall dispatch, argument validation, and tables.
- `user/` — non-syscall userspace glue code needed for libc (not included here)
- `user-tests/` — userspace test programs.
- `os/` — optional larger userland (built when `enable_user_os` is set).
- `test/` — in-kernel test harness (`ktest`) and the kernel test suites.
- `build/` — build configuration: GN toolchains, `features.gni`, linker
  scripts, etc.
- `build_all` — convenience script that builds the current configuration
- `configure` — top-level configuration script; selects GN or SCons,
  architecture, compiler, and feature flags, and sets up `out/`.
- `BUILD.gn` / `SConstruct` / `SConscript` — top-level build files for the
  two supported build systems.
- `sanitizers/` — TSAN support code linked into the kernel.
- `experimental/` — work-in-progress code not part of the default build.
- `grub/` — grub configuration for booting the x86 image.
- `scripts/` — developer scripts.
- `util/` — Python helpers used by `configure` and the build.
- `out-gn/` — GN/ninja build output (generated; not checked in).

Build artifacts land under `out/` (with `out/latest` and `out/latest-<arch>`
symlinks managed by `./configure`).
