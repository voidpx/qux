
pub extern fn _start_us() void;
pub extern fn _end_us() void;
comptime {
    asm (
    \\
    \\.pushsection ".text", "ax", @progbits
    \\.global _start_us, @function
    \\.global _end_us, @function
    \\.align 16
    \\_start_us:
    \\.incbin "../boot/bin/syscall"
    \\
    \\_end_us:
    \\.popsection
    \\

    );
}
