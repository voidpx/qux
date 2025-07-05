const std = @import("std");

pub const X86Flags = enum(u8) {
    X86_EFLAGS_CF_BIT = 0,

    X86_EFLAGS_FIXED_BIT = 1,

    X86_EFLAGS_PF_BIT = 2,

    X86_EFLAGS_AF_BIT = 4,

    X86_EFLAGS_ZF_BIT = 6,

    X86_EFLAGS_SF_BIT = 7,

    X86_EFLAGS_TF_BIT = 8,

    X86_EFLAGS_IF_BIT = 9,

    X86_EFLAGS_DF_BIT = 10,

    X86_EFLAGS_OF_BIT = 11,

    X86_EFLAGS_IOPL_BIT = 12,

    X86_EFLAGS_NT_BIT = 14,

    X86_EFLAGS_RF_BIT = 16,

    X86_EFLAGS_VM_BIT = 17,

    X86_EFLAGS_AC_BIT = 18,

    X86_EFLAGS_VIF_BIT = 19,

    X86_EFLAGS_VIP_BIT = 20,

    X86_EFLAGS_ID_BIT = 21,

};

pub fn bit(f: anytype) u64 {
    const tp = @typeInfo(@TypeOf(f));
    comptime std.debug.assert(tp == .@"enum");
    return @as(u64, 1) << @truncate(@intFromEnum(f));
}

pub fn enumBitOr(comptime flags: anytype) u64 {
    const tp = @typeInfo(@TypeOf(flags));
    comptime std.debug.assert(tp == .@"struct");
    var ret:u64 = 0;
    const fields = tp.@"struct".fields;
    inline for (0..fields.len) |i| {
        const f = fields[i];
        std.debug.assert(@typeInfo(f.type) == .@"enum");
        const flg = @field(flags, f.name); 
        ret |= (1 << @intFromEnum(flg)); 
    }
    return ret;
}

pub fn isIFOn() bool {
    const flags: u64 = asm volatile (
        \\
        \\ pushf
        \\ pop %rax
        \\
        : [ret] "={rax}" (-> u64),
    );
    return (flags & (1 << 9)) > 0;
}

test "test" {
    std.debug.print("0x{x}\n", .{bit(X86Flags.X86_EFLAGS_CF_BIT)});
    std.debug.print("0x{x}\n", .{enumBitOr(.{X86Flags.X86_EFLAGS_CF_BIT, X86Flags.X86_EFLAGS_PF_BIT, X86Flags.X86_EFLAGS_AF_BIT})});

}
