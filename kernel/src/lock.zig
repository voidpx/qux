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
const FUTEX_WAIT		:i32 = 0   ;
const FUTEX_WAKE		:i32 = 1   ;
const FUTEX_FD		        :i32 = 2   ;
const FUTEX_REQUEUE		:i32 = 3   ;
const FUTEX_CMP_REQUEUE	        :i32 = 4   ;
const FUTEX_WAKE_OP		:i32 = 5   ;
const FUTEX_LOCK_PI		:i32 = 6   ;
const FUTEX_UNLOCK_PI		:i32 = 7   ;
const FUTEX_TRYLOCK_PI	        :i32 = 8   ;
const FUTEX_WAIT_BITSET	        :i32 = 9   ;
const FUTEX_WAKE_BITSET	        :i32 = 10  ;
const FUTEX_WAIT_REQUEUE_PI	:i32 = 11  ;
const FUTEX_CMP_REQUEUE_PI	:i32 = 12  ;
const FUTEX_LOCK_PI2		:i32 = 13  ;
const FUTEX_PRIVATE_FLAG	:i32 = 128 ;
const FUTEX_CLOCK_REALTIME	:i32 = 256 ;
const FUTEX_WAIT_PRIVATE	:i32 = (FUTEX_WAIT | FUTEX_PRIVATE_FLAG);
const FUTEX_WAKE_PRIVATE	:i32 = (FUTEX_WAKE | FUTEX_PRIVATE_FLAG);
const console = @import("console.zig");
const time = @import("time.zig");
const mem = @import("mem.zig");
const syscall = @import("syscall.zig");
const FutexMap = std.AutoHashMap(u64, task.WaitQueue);
var futex_map:FutexMap = undefined;
fn doFutex(uaddr:*u32, op:i32, val:u32, utime:?*time.Time, uadd2:?*u32, val3:u32) i64 {
    const t = task.getCurrentTask();
    switch (op) {
        FUTEX_WAIT, FUTEX_WAIT_PRIVATE => {
            return futexWait(t, uaddr, val);
        },
        FUTEX_WAKE, FUTEX_WAKE_PRIVATE => {
            return futexWake(t, uaddr);
        },
        else => {
            console.print("unsupported futex op: {}\n", .{op});
        },

    }
    _=&utime;
    _=&uadd2;
    _=&val3;
    return 0;
}
pub export fn sysFutex(uaddr:*u32, op:i32, val:u32, utime:?*time.Time, uadd2:?*u32, val3:u32)
    callconv(std.builtin.CallingConvention.SysV) i64 {
    return doFutex(uaddr, op, val, utime, uadd2, val3);

}

pub fn futexWake(t:*task.Task, uaddr:*u32) i64 {
    const l = cli();
    defer sti(l);
    const addr:u64 = @intFromPtr(uaddr);
    const p = t.mem.getPageForAddr(addr) orelse return -1;
    const pa = p.getPhyAddr() + (addr & mem.page_mask);
    const wq = futex_map.getPtr(pa) orelse return 0;
    const c = wq.len;
    task.wakeup(wq);
    return @intCast(c);
}

pub fn futexWait(t:*task.Task, uaddr:*u32, val:u32) i64 {
    const l = cli();
    defer sti(l);
    console.print("task {} calling futexWait, 0x{x}, val: {}\n", .{t.id, @as(u64, @intFromPtr(uaddr)), val});
    const addr:u64 = @intFromPtr(uaddr);
    const p = t.mem.getPageForAddr(addr) orelse return -1;
    const pa = p.getPhyAddr() + (addr & mem.page_mask);
    if (uaddr.* != val) return -syscall.EAGAIN; 
    const wq = futex_map.getPtr(pa) orelse blk:{
        futex_map.put(pa, .{}) catch return -1;
        break :blk futex_map.getPtr(pa).?;
    };
    task.wait(wq);
    return 0;
}

pub fn init() void {
    futex_map = FutexMap.init(mem.allocator);
    syscall.registerSysCall(syscall.SysCallNo.sys_futex, &sysFutex);
}


