const config_addr:u16 = 0xcf8;
const config_data:u16 = 0xcfc;
const mem = @import("mem.zig");
pub const BarType = enum(u8) {
    IO,
    MMIO
};

pub const Bar = struct {
    type:BarType,
    addr:u64,
    len:u64
};

pub const PciDev = packed struct {
    bus:u8,
    slot:u5,
    function:u3,
    vendor:u16 = 0,
    device:u16 = 0,
    rev_id:u8 = 0,
    pi:u8 = 0,
    sub_class:u8 = 0,
    class:u8 = 0, 
    pub fn enableBusMastering(dev:*const @This()) void {
        var cmd = readConfig(dev.bus, dev.slot, dev.function, 4, u32);
        cmd |= 4;
        writeConfig(dev.bus, dev.slot, dev.function, 4, cmd);
    }

    pub fn getIrq(dev:*const @This()) u8 {
        const reg = readConfig(dev.bus, dev.slot, dev.function, 0xf << 2, u32);
        const irq = @as(u8, @truncate(reg));
        std.debug.assert(irq < 16); 
        return irq;
    }

    pub fn getBar(dev:*const @This()) [6]?Bar {
        var ret = [_]?Bar{null} ** 6;
        for (0..6) |i| {
            const offset = 0x10 + i*4;
            const bar = readConfig(dev.bus, dev.slot, dev.function, @intCast(offset), u32);
            if (bar & 1 > 0) {
                console.print("IO BAR: 0x{x}\n", .{bar});
            } else if (bar > 0) {
                if (bar & 6 == 4) {
                    console.print("64bit BAR: 0x{x}\n", .{bar});
                }
                writeConfig(dev.bus, dev.slot, dev.function, @intCast(offset), ~@as(u32, 1));
                var mask = readConfig(dev.bus, dev.slot, dev.function, @intCast(offset), u32);
                writeConfig(dev.bus, dev.slot, dev.function, @intCast(offset), bar);
                mask &= ~@as(u32, 0xf);
                const len = if (mask == 0) 0 else ~mask + 1;
                console.print("MMIO BAR: 0x{x}, len: 0x{x}\n", .{bar, len});
                const vaddr = mem.virtualAddr(bar);
                mem.kernelMapVm(vaddr, vaddr + len, bar >> mem.page_shift) catch unreachable;
                ret[i] = Bar{.type = .MMIO, .addr = vaddr, .len = len};
            }
        }
        return ret;
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
            const class = readConfig(this.bus, this.slot, this.function, 0x8, u32);
            return PciDev{.bus = this.bus, .slot = this.slot, .function = this.function, .vendor = @truncate(conf & 0xffff), 
                .device = @truncate(conf >> 16),
            .class = @truncate((class>>24) & 0xff), .sub_class = @truncate((class>>16)&0xff), .pi = @truncate(class&0xff),
                
            };
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
   const addr = getAddr(bus, slot, function, offset);
    io.out(config_addr, addr);
    return io.in(tp, config_data);
}

inline fn getAddr(bus:u8, slot:u5, function:u3, offset:u8) u32 {
    const addr:u32 = (@as(u32, 1) << 31) | (@as(u32, bus) << 16) | (@as(u32, slot) << 11) 
        | (@as(u32, function) << 8) | (offset & 0xfc);
    return addr;
}

fn writeConfig(bus:u8, slot:u5, function:u3, offset:u8, value:anytype) void {
   const addr = getAddr(bus, slot, function, offset);
    io.out(config_addr, addr);
    io.out(config_data, value);
}
const alloc = @import("mem.zig").allocator;
const std = @import("std");
var pci_devs:std.ArrayList(PciDev) = undefined;
pub fn init() void {
    pci_devs = @TypeOf(pci_devs).init(alloc);
    var pci_it = PciDevIter{};
    while (pci_it.next()) |d| {
        //console.print("pci vendor: 0x{x}, device: 0x{x}, " 
        //++ " class: 0x{x}, sub_class: 0x{x}, prog_if: 0x{x}\n", 
        //.{d.vendor, d.device, d.class, d.sub_class, d.pi});
        pci_devs.append(d) catch unreachable;
        //d.readBAR();
    }
}

pub fn findDev(vendor:u16, dev:u16) ?PciDev {
    for (0..pci_devs.items.len) |i| {
        const p = pci_devs.items[i];
        if (p.vendor == vendor and p.device == dev) return p;
    }
    return null;
}


