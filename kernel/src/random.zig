const sys = @import("syscall.zig");
const std = @import("std");
const lock = @import("lock.zig");

var seed:u32 = 2463534242;
fn getRnd() u32 {
    const l = lock.cli();
    defer lock.sti(l);
    seed ^= seed << 13;
    seed ^= seed >> 17;
    seed ^= seed << 5;
    return seed;
}

pub export fn sysGetRandom(buf:[*]u8, bufsiz:usize, flags:i32)
    callconv(std.builtin.CallingConvention.SysV) i64 {
    const w = bufsiz/@sizeOf(u32);
    for (0..w) |i| {
        const r = getRnd();
        const p:*align(1) u32 = @ptrCast(&buf[i*@sizeOf(u32)]);
        p.* = r;
    }
    const r = getRnd();
    const start = w * @sizeOf(u32);
    for (0..bufsiz%@sizeOf(u32)) |i| {
        buf[start + i] = @truncate((r>>@truncate(i*8)) & 0xff);
    }
    _=&flags;
    return @intCast(bufsiz);

}

pub fn init() void {
    sys.registerSysCall(sys.SysCallNo.sys_getrandom, &sysGetRandom);
}

