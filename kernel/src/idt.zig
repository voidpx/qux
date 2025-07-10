const console = @import("console.zig");
const as = @import("asm.zig");
const std = @import("std");
const pic = @import("pic.zig");
const num_ex = 32;
const num_hwint = 16;
pub const IntState = extern struct {
    syscall_no:i64, // on interrupt, it's -1, on syscall, it's the syscall no 
    r15: u64,
    r14: u64,
    r13: u64,
    r12: u64,
    rbp: u64,
    rbx: u64,
    r11: u64,
    r10: u64,
    r9: u64,
    r8: u64,
    rax: u64,
    rcx: u64,
    rdx: u64,
    rsi: u64,
    rdi: u64,
    vector: u64,
    err_code: u64,
    rip: u64,
    cs: u64,
    rflags: u64,
    // only available from user space
    rsp: u64,
    ss: u64,
};
const IdtEntry = packed struct { 
    offset1: u16,
    selector: u16, 
    ist: u3, 
    resv1: u5 = 0, 
    gate_type: u4, 
    resv2: u1 = 0, 
    dpl: u2, 
    p: u1 = 1, 
    offset2: u16, 
    offset3: u32 = 0, 
    resv3: u32 = 0 };

const Idtr = packed struct { limit: u16, base: u64 };

const IDT_NUM = 256;

var idt: [IDT_NUM]IdtEntry align(16) = undefined;
const INT_ENTRY_SIZE = 9; // size of the following generated code of idt entry
comptime {
    asm (
        \\
        \\.pushsection ".text", "ax", @progbits
        \\.global __exception_handlers;
        \\.macro idt_entry vec, err_code=0
        \\0:
        \\.if \err_code == 0
        \\  pushq $0 
        \\.endif
        \\ pushq $\vec
        \\ jmp _idt_entry
        \\.fill 9-(.-0b), 1, 0xcc 
        \\.endm 
        \\
        \\__exception_handlers:
        \\ idt_entry 0
        \\ idt_entry 1
        \\ idt_entry 2
        \\ idt_entry 3
        \\ idt_entry 4
        \\ idt_entry 5
        \\ idt_entry 6
        \\ idt_entry 7
        \\ idt_entry 8, 1
        \\ idt_entry 9
        \\ idt_entry 10, 1
        \\ idt_entry 11, 1
        \\ idt_entry 12, 1
        \\ idt_entry 13, 1
        \\ idt_entry 14, 1
        \\ idt_entry 15
        \\ idt_entry 16
        \\ idt_entry 17, 1
        \\ idt_entry 18
        \\ idt_entry 19
        \\ idt_entry 20
        \\ idt_entry 21
        \\ idt_entry 22
        \\ idt_entry 23
        \\ idt_entry 24
        \\ idt_entry 25
        \\ idt_entry 26
        \\ idt_entry 27
        \\ idt_entry 28
        \\ idt_entry 29
        \\ idt_entry 30, 1
        \\ idt_entry 31
        \\
        \\int_vec = 0x20
        \\.rept 16
        \\  idt_entry int_vec
        \\  int_vec = int_vec+1
        \\.endr
        \\
        \\_idt_entry:
        \\ entry_call handle_interrupt, exit_call
        \\.popsection
    );
}

const ex = @extern([*][INT_ENTRY_SIZE]u8,
    std.builtin.ExternOptions{ .name = "__exception_handlers" });

var exception_handlers = [_]?*const fn(*IntState) void{null} ** num_ex;

//var nested:i32 = 0;
const k_start = @extern(*const u8, .{ .name = "_stext" });
const k_end = @extern(*const u8, .{ .name = "_etext" });
const task = @import("task.zig");
const time = @import("time.zig");
export fn handle_interrupt(state: *IntState, vec: u64) callconv(std.builtin.CallingConvention.SysV) void {
    const cur = task.getCurrentTask();
    //if (state.rsp < cur.stack + 128) {
    //    std.debug.panic("stackoverflow\n", .{});
    //}
    //nested += 1;
    //defer nested -=1;
    //if (state.rip < @intFromPtr(k_start) or state.rip >= @intFromPtr(k_end)) {
    //    var x:i32 = 3;
    //    _=&x;
    //    //console.print("", .{});
    //    //
    //    //console.print("rip out or text section: 0x{x}", .{state.rip});
    //    //if (true) {
    //    //    console.print("shouldn't reach here\n", .{});
    //    //}
    //}

    switch (vec) {
        0...num_ex-1 => 
        {   
            var x:i32=0xabcd;
            _=&x;
            handleException(state, vec);
        },
        else => handleHwInterrupt(state, vec - 0x20)
    }

    cur.cpuExit();

    if (vec == 0xd) {
        console.print("GP\n", .{});
    }
    if (cur.needResched()) {
        task.schedule();
    } else {
        cur.cpuEnter();
        //console.print("no sched\n", .{});
    }
    // NOTE: console print is not safe in interrupt context
    // console.print("exception: {}\n", .{vec});
    // console.print("regs: r15:{x}, r14:{x}, r13:{x}, r12:{x}, rbp:{x}, rbx:{x}, r11:{x}, r10:{x}, r9:{x}, r8:{x}, rax:{x}, rcx:{x}, rdx:{x}, rsi:{}, rdi:{}\n", .{ regs.r15, regs.r14, regs.r13, regs.r12, regs.rbp, regs.rbx, regs.r11, regs.r10, regs.r9, regs.r8, regs.rax, regs.rcx, regs.rdx, regs.rsi, regs.rdi });
    //console.print("error code:{x}, rip:{x}, cs:{x}, rflags:{x}\n", .{ state.err_code, state.rip, state.cs, state.rflags });
    
    //if (nested > 1) {
        //console.print("nested:{}, rip:0x{x}\n", .{nested, state.rip});
    //}


    //===================================================
    //if (vec == 0xd) {
    //    console.print("GP after sched\n", .{});
    //}
    //===================================================
}

pub fn registerExceptionHandler(vec:u64, handler:?*const fn(*IntState) void) void {
    std.debug.assert(vec < num_ex);
    exception_handlers[vec] = handler;
}

fn handleException(state: *IntState, vec:u64) void {
    console.print("exception: 0x{x}, rip: 0x{x}\n", .{vec, state.rip});
    if (exception_handlers[vec]) |h| {
        h(state);
    } else {
        std.debug.panic("unhandled exeption: {}", .{vec});
    }
}

fn handleHwInterrupt(state: *IntState, irq:u64) void {
    _=&state;
    const handler = handlers[irq];
    if (handler) |h| {
        h.handler();
        pic.sendEOI(@intCast(irq));
    } else {
        console.print("unhandled interrupt: 0x{x}\n", .{irq}); 
    }
}

var idtr: Idtr = undefined;
pub fn init() void {
    for (idt[0..num_ex+num_hwint], 0..) |_, i| {
        const offset: u64 = @intFromPtr(&ex[i]);
        const off1: u16 = @intCast(offset & 0xffff);
        const off2: u16 = @intCast((offset >> 16) & 0xffff);
        const off3: u32 = @intCast(offset >> 32);
        const gt: u4 = if (i == 2 or i >= 0x20) 0b1110 else 0b1111;
        idt[i] = IdtEntry{ 
            .offset1 = off1, 
            .selector = 8, 
            .ist = 0, 
            .dpl = 0, 
            .offset2 = off2,
            .gate_type = gt,
            .offset3 = off3};
    }
    idtr.base = @intFromPtr(&idt);
    idtr.limit = @sizeOf(@TypeOf(idt)) - 1;
    asm volatile (
        \\ lidt (%rax)
        \\
        :
        : [idtr] "{rax}" (&idtr),
    );
}

const IrqHandler = struct {
    handler: *const fn() void,
    next: ?*IrqHandler = null
};
const MAX_INT = 16;
var handlers = [_]?IrqHandler{null} ** MAX_INT;

pub fn registerIrq(irq: u8, h: *const fn() void) void {
    handlers[irq] = IrqHandler{.handler = h};
}


