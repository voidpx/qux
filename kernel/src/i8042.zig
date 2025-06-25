const idt = @import("idt.zig");
const io = @import("io.zig");
const input = @import("input.zig");
const irq:u8 = 1;
const data_reg:u16 = 0x60;
const cmd_reg:u16 = 0x64;

fn i8042Interrupt() void {
   const c = io.in(u8, data_reg);
    // handle input
    input.handleInput(c);
}

pub fn initI8042() void {
   idt.registerIrq(irq, i8042Interrupt);
   @import("pic.zig").enable(irq);
}


