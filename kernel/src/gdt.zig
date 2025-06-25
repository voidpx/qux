
const kcsi = 1;
const kdsi = 2;
const ucsi = 3;
const udsi = 4;
const tssi = 5;
pub const kcs = kcsi << 3; 
pub const kds = kdsi << 3;
pub const ucs = (ucsi << 3) + 3;
pub const uds = (udsi << 3) + 3;
pub const tss = tssi << 3;
const ndesc = 8;

//const Gdt = struct { entries: [8]u64 = [_]u64{0} ** 8 };
const Gdt = struct { entries: [ndesc]Entry };
const Gdtr = packed struct { len: u16, ptr: u64 };

var gdt: Gdt align(16) = undefined;
var gdtr: Gdtr align(16) = undefined;

pub const Tss = extern struct {
    reserved1:u32 = 0,
    sp0:u64 align(1) = 0,
    sp1:u64 align(1) = 0,
    sp2:u64 align(1) = 0,
    reserved2:u64 align(1) = 0,
    ist: [7]u64 align(1) = [_]u64{0} ** 7,
    reserved3:u32 = 0,
    reserved4:u32 = 0,
    reserved5:u16 = 0,
    io_map_base:u16 = 0,
};

pub fn loadTSS(desc: *Tss) void {
    const base:u64 = @intFromPtr(desc);

    gdt.entries[tssi] = .{.limit0 = @sizeOf(Tss) - 1, .base0=@truncate(base & 0xffff),
        .base1 = @truncate((base >> 16) & 0xff),
        .base2 = @truncate((base >> 24) & 0xff),
        .access = 0x89};
    const ptr = &gdt.entries[tssi+1];
    const tssex:*u64 = @ptrCast(ptr);
    tssex.* = @truncate(base >> 32);

    asm volatile("ltr %ax"::[tss] "{rax}" (tss));
}

const Entry = packed struct {
    limit0:u16 = 0,
    base0:u16 = 0,
    base1:u8 = 0,
    access:u8 = 0,
    limit1:u4 = 0,
    flags:u4 = 0,
    base2:u8 = 0
};

pub fn init() void {
    //gdt.entries[kcsi] = 0x00af9a000000ffff;
    //gdt.entries[kdsi] = 0x00af92000000ffff;
    //gdt.entries[ucsi] = 0x00afda000000ffff;
    //gdt.entries[udsi] = 0x00afd2000000ffff;
    gdt.entries[kcsi] = .{.limit0 = 0xffff, .access = 0x9a, .limit1 = 0xf, .flags = 0xa};
    gdt.entries[kdsi] = .{.limit0 = 0xffff, .access = 0x92, .limit1 = 0xf, .flags = 0xa};
    gdt.entries[ucsi] = .{.limit0 = 0xffff, .access = 0xfa, .limit1 = 0xf, .flags = 0xa};
    gdt.entries[udsi] = .{.limit0 = 0xffff, .access = 0xf2, .limit1 = 0xf, .flags = 0xa};
    gdtr = Gdtr{ .len = @sizeOf(Gdt) - 1, .ptr = @intFromPtr(&gdt) };

    asm volatile (
        \\
        \\ lgdt (%rax) 
        \\ mov %esi, %eax
        \\ movl %eax, %ds
        \\ movl %eax, %es
        \\ movl %eax, %ss
        \\ movl %eax, %gs
        \\ movl %eax, %fs
        \\ lea 1f(%rip), %rax
        \\ push %rdi
        \\ push %rax
        \\ lretq
        \\
        \\1:
        \\
        :
        : [gdtr] "{rax}" (&gdtr),
          [kcs] "{edi}" (kcs),
          [kds] "{esi}" (kds),
    );
}
