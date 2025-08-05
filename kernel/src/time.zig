const std = @import("std");
const task = @import("task.zig");
pub const Timer = struct {
    ctx: ?*anyopaque = null,
    on_list :?*anyopaque = null,
    node: TimerList.Node = .{.prev = null, .next = null, .data = undefined}, // private
    next_fire:i64 = 0, // in milli seconds
    repeat:i64 = 0, // in milli seconds
    func: *const fn(t: *Timer) void,
};

const TimerList = std.DoublyLinkedList(*Timer);
var timers = TimerList{};

pub const Time = extern struct {
    sec: i64 align(1) = 0,
    nsec: i64 align(1) = 0,

    pub fn getAsNanoSeconds(t: *const @This()) i64 {
        return t.sec*nsec_per_sec + t.nsec;
    }

    pub fn getAsMilliSeconds(t: *const @This()) i64 {
        return t.sec*msec_per_sec + @divTrunc(t.nsec, nsec_per_milli_sec);
    }

    pub fn add(self:*@This(), t:Time) *@This() {
        addTime(self, t);
        return self;
    }
};
pub const nsec_per_sec:u64 = 1000000000;
pub const nsec_per_milli_sec:u64 = 1000000;
pub const nsec_per_micro_sec:u64 = 1000;
pub const msec_per_sec:u64 = 1000;
pub const nsec_per_tick = nsec_per_sec / pit.tick_hz;

var time: Time = .{};

pub fn setTime(t: Time) void {
    time = t;
}

pub fn addSeconds(sec: i64) void {
    time.sec += sec;
}

pub fn addNanoSeconds(nsec: i64) void {
    addTime(&time, .{.nsec = nsec});
}

pub fn addTime(t: *Time, delta: Time) void {
    t.sec += delta.sec;
    const nano = t.nsec + delta.nsec;
    t.sec += @divTrunc(nano, nsec_per_sec);
    t.nsec = @rem(nano, nsec_per_sec);
}

pub fn addMilliSeconds(msec : i64) void {
    addNanoSeconds(msec * nsec_per_milli_sec);
}

fn wakeUp(t:*Timer) void {
    task.wakeup(@as(*task.WaitQueue, @alignCast(@ptrCast(t.ctx))));
}

fn onExit(ctx:?*anyopaque, _:*task.Task) void {
    const timer:*Timer = @ptrCast(@alignCast(ctx));
    removeTimer(timer);
    removeFromExpired(timer);
}

const console = @import("console.zig");
pub fn sleep(t: *const Time, rem:?*Time) i32 {
    if (rem) |r| r.* = .{};
    var now = getTime();
    var dup = now;
    const expire = dup.add(t.*);
    if (expire.getAsMilliSeconds() <= now.getAsMilliSeconds()) return 0;
    var cur = task.getCurrentTask();
    const v = lock.cli();
    defer lock.sti(v);
    if (cur.state == .dead) task.schedule();
    cur.state = .sleep;
    var wq = task.WaitQueue{};
    var node:task.WaitQueue.Node = .{.data = cur};
    wq.append(&node);
    var timer = Timer{.ctx = &wq, .func = &wakeUp, .repeat = 0, .next_fire = expire.getAsMilliSeconds()};
    addTimer(&timer);
    var l = task.TaskListener{.ctx = &timer, .func = &onExit};
    cur.registerExitListener(&l);
    task.scheduleWithIF();
    cur.removeExitListener(&l);

    removeTimer(&timer); // in case it wasn't waked up by the timer
    now = getTime();
    if (expire.getAsMilliSeconds() <= now.getAsMilliSeconds()) return 0;
    if (rem) |r| {
        const ms = expire.getAsMilliSeconds() - now.getAsMilliSeconds();
        r.sec = @divFloor(ms, 1000);
        r.nsec = @mod(ms, 1000);
        return -1;
    }
    return -1;
}

pub fn getTime() Time {
    var t = time;
    const boot_time = getBootTime();
    addTime(&t, .{.nsec = @as(i64, @intCast(boot_time))});
    return t;
}
const rtc = @import("rtc.zig");
const pit = @import("pit.zig");
const mem = @import("mem.zig");
const con = @import("console.zig");
const syscall = @import("syscall.zig");
pub fn init() void {
    const rt = rtc.readRTC();
    var now = makeTime(rt);
    const boot_time = getBootTime();
    addTime(&now, .{.nsec = -@as(i64, @intCast(boot_time))});
    time = now;
    con.timeReady(&getBootTime);
    syscall.registerSysCall(syscall.SysCallNo.sys_nanosleep, &sysNanoSleep);
    syscall.registerSysCall(syscall.SysCallNo.sys_clock_nanosleep, &sysCloskNanoSleep);
    syscall.registerSysCall(syscall.SysCallNo.sys_clock_gettime, &sysClockGetTime);
    syscall.registerSysCall(syscall.SysCallNo.sys_time, &sysTime);
}

pub export fn sysTime(tp:?*i64) callconv(std.builtin.CallingConvention.SysV) i64 {
    const t =getTime();   
    if (tp) |p| {
        p.* = t.sec;
    }
    return t.sec;
}

pub export fn sysClockGetTime(clock_id:i32, ret:*Time) callconv(std.builtin.CallingConvention.SysV) i64 {
    _=&clock_id;
    const t =getTime();   
    ret.* = t;
    return 0;
}

pub export fn sysNanoSleep(duration:*Time, rem:?*Time) callconv(std.builtin.CallingConvention.SysV) i64 {
    return sleep(duration, rem);
}

pub export fn sysCloskNanoSleep(clk_id: u32, flags:u32, duration:*Time, rem:?*Time) callconv(std.builtin.CallingConvention.SysV) i64 {
    _=&clk_id;
    _=&flags;
    return sleep(duration, rem);
}

fn getBootTime() u64 {
    return pit.getTicks() * nsec_per_tick;
}

var expired_timers = TimerList{};
fn nextExpired() ?*Timer {
    const l = lock.cli();
    defer lock.sti(l);
    const n = expired_timers.popFirst() orelse return null;
    n.data.on_list = null;
    return n.data;
}
pub fn timerRoutine(_:?*anyopaque) u16 {
    while (true) {
        const now = getTime().getAsMilliSeconds();
        while (nextExpired()) |t| {
            t.func(t);
            if (t.repeat > 0) {
                t.next_fire = now + t.repeat;
                addTimer(t);
            }
        }
        task.wait(&exp_timer_wq);
    }
}

var exp_timer_wq = task.WaitQueue{};
fn addToExpired(t:*Timer) void {
    const l = lock.cli();
    defer lock.sti(l);
    t.on_list = &expired_timers;
    expired_timers.append(&t.node);
}

pub fn runTimers() void {
    const l = lock.cli();
    defer lock.sti(l);
    var node = timers.first;
    const now = getTime().getAsMilliSeconds();
    while (node) |n| {
        const t = n.data;
        node = n.next;
        if (t.next_fire <= now) {
            removeTimer(t);
            addToExpired(t); 
        }
    }
    if (expired_timers.len > 0) {
        task.wakeup(&exp_timer_wq);
    }
}

const lock = @import("lock.zig");
pub fn addTimer(timer: *Timer) void {
    const v = lock.cli();
    defer lock.sti(v);
    timer.node.data = timer;
    timer.node.prev = null;
    timer.node.next = null;
    timer.on_list = &timers;
    timers.append(&timer.node);
}

pub fn removeTimer(timer: *Timer) void {
    const v = lock.cli();
    defer lock.sti(v);
    if (timer.on_list == @as(*anyopaque, @ptrCast(&timers))) {
        timers.remove(&timer.node);
        timer.node.prev = null;
        timer.node.next = null;
        timer.on_list = null;
    }

}
fn removeFromExpired(timer: *Timer) void {
    const v = lock.cli();
    defer lock.sti(v);
    if (timer.on_list == @as(*anyopaque, @ptrCast(&expired_timers))) {
        expired_timers.remove(&timer.node);
        timer.node.prev = null;
        timer.node.next = null;
        timer.on_list = null;
    }

}

fn makeTime(t: rtc.RTC) Time {
    var year: i64 = t.year;
    var month: i64 = @as(i64, t.month) - 2;
    if (month <= 0) {
        month += 12;
        year -= 1;
    }
    const sec = (((@divTrunc(year, 4) - @divTrunc(year, 100) + @divTrunc(year, 400) // extra days from leap years
        + @divTrunc(367 * month,12) + t.day // days in current unfinished year
        + year * 365 // days in all finished years
        - 719499 // days until 1970
        ) * 24 + t.hour
        ) * 60 + t.minute
        ) * 60 + t.second;
    return .{.sec = sec};
}
