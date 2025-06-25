const std = @import("std");
const task = @import("task.zig");
pub const Lock = i32;
pub const unlocked:i32 = 0;

pub fn tryLock(l:*Lock) bool {
    if (@cmpxchgStrong(Lock, l, 0, 1, 
        std.builtin.AtomicOrder.acquire, 
        std.builtin.AtomicOrder.acquire)) |_| {
        return false;
    }
    return true;
}

pub fn lock(l:*Lock) void {
    while(@cmpxchgWeak(Lock, l, 0, 1, 
        std.builtin.AtomicOrder.acquire, 
        std.builtin.AtomicOrder.acquire)) |_| {
        task.schedule();
    }
}

pub fn unlock(l:*Lock) void {
    std.debug.assert(@atomicLoad(Lock, l, std.builtin.AtomicOrder.unordered) == 1);
    @atomicStore(Lock, l, 0, std.builtin.AtomicOrder.release);
}

pub inline fn cli() bool {
    const flags:u64 = asm volatile(
    \\
    \\ pushf
    \\ pop %rax
    \\
    : [ret] "={rax}" (-> u64)
    :
    );
    if ((flags & (1 << 9)) > 0) {
        asm volatile("cli");
        return true;
    }
    return false; // interrupt already disabled
}

pub inline fn sti(v:bool) void {
    if (v) {
        asm volatile("sti");
    }
}

