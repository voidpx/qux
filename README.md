# A toy OS

Qux is a toy operating system for x64 written in zig.

![It can run doom!](doom.gif)

### Build and run

- can only be built in Linux on x64 with grub installed. 
- the `kernel` directory contains the kernel source code
- the `boot` directory contains some utility for bootstrap. steps to build:
    - run `zig build` under `kernel` to build the kernel
    - `mkimg test.img` make a disk image named `test.img` with grub installed to boot the OS with multiboot2.
    - `build`  build everything under `boot` directory and copy the kernel to the disk image built above and start QEMU to run it

### What's implemented

- [x] memory management
- [x] basic process management/scheduling
- [x] basic ATA driver
- [x] ext2 file system, read only so far
- [x] syscalls, trying to implement Linux syscalls, so that userspace programs for Linux could hopefully run on Qux 
- [x] basic ELF loader
- [x] can run doom(doomgeneric), kind of :), key handling is still to be done

### TODO

- [ ] network stack
- [ ] SMP support
- [ ] more syscalls
- [ ] port some usefull userspace programs

