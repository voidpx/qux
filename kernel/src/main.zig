const std = @import("std");
const console = @import("console.zig");
const idt = @import("idt.zig");
const bi = @import("bootinfo.zig");
const cpu = @import("cpu.zig");
const kbd = @import("i8042.zig");
const pic = @import("pic.zig");
const mem = @import("mem.zig");
const rtc = @import("rtc.zig");
const pit = @import("pit.zig");
const time = @import("time.zig");
const pci = @import("pci.zig");
const task = @import("task.zig");
const driver = @import("driver.zig");
pub const Panic = @import("panic.zig");
// XXX: newer version would work without the following line
pub const panic: fn(msg: []const u8, ert: ?*std.builtin.StackTrace, ra: ?usize) noreturn = Panic.call; 


//test
//const us =@import("userspace.zig");

const syscall = @import("syscall.zig");
const fs = @import("fs.zig");
const font = @import("ui/font.zig");
const fbcon = @import("ui/fbcon.zig");
const rand = @import("random.zig");
const ipc = @import("ipc.zig");

export fn startKernel(b: *bi.BootInfo) callconv(std.builtin.CallingConvention.SysV) void {
    cpu.enableSSE() catch unreachable; // don't enable sse in kernel
    //bi.init(b);
    @import("asm.zig").init(); // make sure the asm macros are available early
    console.init();
    font.init();
    fbcon.init(b.getMb2());
    console.print("Qux kernel starting...\n", .{});
    idt.init();
    mem.init(b);

    pic.init();
    pit.pit_init();
    time.init();
    kbd.initI8042();

    driver.init();
    rand.init();

    syscall.init();
    fs.init();

    ipc.init();
    task.init();
    exec.init();

    pic.sti();
    
    kthread.createUserThread("init", &initThread, null);

    //kthread.createKThread("loop", &loop, null);

    idleLoop();
}

const flags = @import("flags.zig");
fn idleLoop() noreturn {
    while (true) {
        //const v = lock.cli();
        //task.reapTasks();
        //lock.sti(v);
        task.schedule();
        //if (!flags.isIFOn()) {
        //    console.print("WRONG\n", .{});
        //}
        asm volatile("sti; hlt");
    }
}

//DEBUG
fn loop(_: ?*anyopaque) u16 {
    for (0..std.math.maxInt(usize)) |i| {
        if (i % 10000000 == 0) {
           console.print("looping\n", .{});
        }
        //task.schedule();
        asm volatile("pause");
    }
    return 0;
}

const exec = @import("exec.zig");
fn runShell(_:?*anyopaque) u16 {
    //const args = [_]?[*:0]const u8 {"/bin/doomgeneric", "-iwad", "/bin/freedoom1.wad", null};
    //const envp = [_]?[*:0]const u8 {"testenv1=ok", "testenv2=no", null};
    //_ = exec.sysExecve("/bin/us", @constCast(@ptrCast(&args)), @constCast(@ptrCast(&envp)));
    //_ = exec.sysExecve("/bin/doomgeneric", @constCast(@ptrCast(&args)), @constCast(@ptrCast(&envp)));
    const r = exec.sysExecve("/bin/dash", null, null);
    if (r == -1) {
        std.debug.panic("unable to start shell\n", .{});
    }
    return 0;
}

const lock = @import("lock.zig");
const kthread = @import("kthread.zig");
fn reaper(_:?*anyopaque) u16 {
    var cur = task.getCurrentTask();
    while (true) {
        // do reaping
        const v = lock.cli();
        task.reapTasks();
        cur.state = .blocked;
        lock.sti(v);
        task.schedule();
    }
    unreachable;

}

fn initThread(_:?*anyopaque) u16 {
    pci.walkPci();
    //task.startSchedRoutine();

    //XXX: debug mem
    //kthread.createKThread("mem-watch", &printMemStat, null);

   //     const m = mem.getMemStat();
   //     console.print("memory: used pages: {}, free pages: {}, total tasks: {}\n", .{m.used_pages, m.free_pages, task.getTotalTasks()});
   //     console.print("runq, size: {}, capacity: {}\n", .{task.runq.len, task.runq.capacity()});
    //time.sleep(.{.sec = 3});

    //testSched();

    //kthread.createKThread("reaper", &reaper, null);
    return runShell(null);
    //kthread.createUserThread("init", &runShell, null);

    //var cur = task.getCurrentTask();
    //while (true) {
    //    // do reaping
    //    const v = lock.cli();
    //    task.reapTasks();
    //    cur.state = .blocked;
    //    lock.sti(v);
    //    task.schedule();
    //}
    //unreachable;
}

fn printMemStat(_: ?*anyopaque) u16 {
    while (true) {
        time.sleep(.{.sec = 5});
        task.runq.shrinkAndFree(@min(@max(task.runq.len, 10), task.runq.capacity()));
        const m = mem.getMemStat();
        console.print("memory: used pages: {}, free pages: {}, total tasks: {}\n", .{m.used_pages, m.free_pages, task.getTotalTasks()});
        console.print("runq, size: {}, capacity: {}\n", .{task.runq.len, task.runq.capacity()});
    }

}

//fn newKThread(name:[]const u8, f:*const fn(arg: ?*anyopaque) u16, a: ?*anyopaque) void {
//    var arg = task.CloneArgs{.arg = a, .name = name, .func = f};
//    task.clone(&arg) catch unreachable;
//}

fn testSched() void {
    var buf = [_]u8{0} ** 32;
    for (0..100) |i| {
        const slice:[]u8 = &buf;
        const name = std.fmt.bufPrint(slice, "test thread {}", .{i}) catch unreachable;
        kthread.createKThread(name, &testThread, null);
    }
}

fn testThread(_:?*anyopaque) u16 {
    for (0..3) |i| {
        console.print("{s} .. {}\n", .{task.getCurrentTask().getName(), i});
        time.sleep(.{.sec = 3});
    }
    return 0;
}

fn testPanic() void {
    std.debug.panic("test panic", .{});
}
