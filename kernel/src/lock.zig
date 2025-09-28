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
const FUTEX_WAIT		= 0   ;
const FUTEX_WAKE		= 1   ;
const FUTEX_FD		= 2   ;
const FUTEX_REQUEUE		= 3   ;
const FUTEX_CMP_REQUEUE	= 4   ;
const FUTEX_WAKE_OP		= 5   ;
const FUTEX_LOCK_PI		= 6   ;
const FUTEX_UNLOCK_PI		= 7   ;
const FUTEX_TRYLOCK_PI	= 8   ;
const FUTEX_WAIT_BITSET	= 9   ;
const FUTEX_WAKE_BITSET	= 10  ;
const FUTEX_WAIT_REQUEUE_PI	= 11  ;
const FUTEX_CMP_REQUEUE_PI	= 12  ;
const FUTEX_LOCK_PI2		= 13  ;
const FUTEX_PRIVATE_FLAG	= 128 ;
const FUTEX_CLOCK_REALTIME	= 256 ;
const time = @import("time.zig");
const mem = @import("mem.zig");
const syscall = @import("syscall.zig");
const FutexMap = std.AutoHashMap(u64, task.WaitQueue);
var futex_map:FutexMap = undefined;
pub export fn sysFutex(uaddr:*u32, op:i32, val:u32, utime:?*time.Time, uadd2:?*u32, val3:u32)
    callconv(std.builtin.CallingConvention.SysV) i64 {
    if (uaddr.* != val) return syscall.EAGAIN; 
    const l = cli();
    defer sti(l);
    const t = task.getCurrentTask();
    const p = t.mem.getPageForAddr(uaddr) orelse return -1;
    const addr:u64 = @intFromPtr(uaddr);
    const pa = p.getPhyAddr() + (addr & mem.page_shift);
    

}
pub fn init() void {
    futex_map = FutexMap.init(mem.allocator);
}


