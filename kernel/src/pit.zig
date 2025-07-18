pub const tick_hz:u32 = 100;
const pit_hz:u32 = 1193182;
const latch:u16 = @truncate((pit_hz + tick_hz/2)/tick_hz);

const port_pit_cmd:u16 = 0x43;
const port_pit_c0:u16 = 0x40;

const io = @import("io.zig");
const pic = @import("pic.zig");
const console = @import("console.zig");
const idt = @import("idt.zig");
const task = @import("task.zig");

const irq:u8 = 0;
var ticks:u64 = 0;

pub fn pit_init() void {
    io.out(port_pit_cmd, @as(u8, 0x34));
    io.out(port_pit_c0, @as(u8, @truncate(latch & 0xff)));
    io.out(port_pit_c0, @as(u8, @truncate(latch >> 8)));
    idt.registerIrq(irq, pit_interrupt);
    pic.enable(irq);
}

const time = @import("time.zig");
const mem = @import("mem.zig");
const lock = @import("lock.zig");
fn pit_interrupt(state:*idt.IntState) void {
    const l = lock.cli();
    defer lock.sti(l);
    ticks += 1;
    _=&state; 
    //if (state.rip < mem.user_max) {
        // userspace interrupted
        const cur = task.getCurrentTask();
        @import("time.zig").runTimers();
        if (!task.preemptDisabled() and time.getTime().getAsMilliSeconds() - cur.sched.cpu_enter > 100) {
            cur.resched();
        }

    //}

    //console.print("pit timer interrupt, ticks: {}\n", .{ticks});    
}

pub fn getTicks() u64 {
    return ticks;
}

