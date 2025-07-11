const config_addr:u16 = 0xcf8;
const config_data:u16 = 0xcfc;

const PciDev = packed struct {
    bus:u8,
    slot:u5,
    function:u3,
    vendor:u16,
    device:u16,
    class:u8,
    sub_class:u8,
    pi:u8,
    fn readBAR(dev:*const @This()) void {
        for (0..6) |i| {
            const offset = 0x10 + i*4;
            const bar = readConfig(dev.bus, dev.slot, dev.function, @intCast(offset), u32);
            if (bar & 1 > 0) {
                console.print("IO BAR: 0x{x}\n", .{bar});
            } else {
                console.print("MMIO BAR: 0x{x}\n", .{bar});
                if (bar & 6 == 4) {
                    console.print("64bit BAR: 0x{x}\n", .{bar});
                }
            }
        }
    }
};

const PciDevIter = struct {
    bus:u8 = 0,
    slot:u5 = 0,
    function:u3 = 0,
    _done:bool = false,
    fn next(this: *@This()) ?PciDev {
        while (!this._done) {
            defer this._done = !this._next();
            const conf = readConfig(this.bus, this.slot, this.function, 0, u32);
            if ((conf & 0xffff) == 0xffff) {
                continue;
            }
            const class = readConfig(this.bus, this.slot, this.function, 0xb, u32);
            return PciDev{.bus = this.bus, .slot = this.slot, .function = this.function, .vendor = @truncate(conf & 0xffff), 
                .device = @truncate(conf >> 16),
            .class = @truncate((class>>24) & 0xff), .sub_class = @truncate((class>>16)&0xff), .pi = @truncate(class&0xff)};
        }
        return null;
    }   

    fn _next(this: *@This()) bool {
        if (this.function < 7) {
            this.function += 1; 
            return true;
        }
        this.function = 0;
        if (this.slot < 31) {
            this.slot += 1;
            return true;
        }
        this.slot = 0;
        if (this.bus < 255) {
            this.bus += 1;
            return true;
        }
        return false;
    }

};
const console = @import("console.zig");
const io = @import("io.zig");
fn readConfig(bus:u8, slot:u5, function:u3, offset:u8, comptime tp:type) tp {
   const addr:u32 = (@as(u32, 1) << 31) | (@as(u32, bus) << 16) | (@as(u32, slot) << 11) 
    | (@as(u32, function) << 8) | (offset & 0xfc);
    io.out(config_addr, addr);
    return io.in(tp, config_data);
}
const alloc = @import("mem.zig").allocator;
const std = @import("std");
pub fn init() void {
    var pci_it = PciDevIter{};
    while (pci_it.next()) |d| {
        console.print("pci vendor: 0x{x}, device: 0x{x}, class: 0x{x}, sub_class: 0x{x}, prog_if: 0x{x}\n", 
        .{d.vendor, d.device, d.class, d.sub_class, d.pi});
        d.readBAR();
    }
}


