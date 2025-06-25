pub fn io_wait() void {
    out(0x80, @as(u8, 0));
}

pub const IOError = error {ReadError, WriteError};

pub fn in(comptime T:type, port:u16) T {
    comptime var ins: []const u8 = undefined;
    ins = switch (T) {
        u8 => "inb",
        u16 => "inw",
        u32 => "inl",
        else => unreachable
    };
    
    return asm volatile(
    ins ++
    \\ %[port], %[ret]
    :[ret] "={eax}" (->T)
    :[port] "{dx}" (port)

    );
}

pub fn out(port:u16, value: anytype) void {
    comptime var ins: []const u8 = undefined;
    ins = switch (@TypeOf(value)) {
        u8 => "outb",
        u16 => "outw",
        u32 => "outl",
        else => unreachable 
    };

    asm volatile(ins ++
    \\ %[value], %[port]
    :
    :[value] "{eax}" (value),
     [port] "{dx}" (port)

    );
}

