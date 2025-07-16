const pci = @import("../../pci.zig");
const rtl8139_vendro = 0x10ec;
const rtl8139_device = 0x8139;
const Rtl8139 = struct {
    pd:pci.PciDev,
    bar_addr:u64 = 0,
    bar_len:u64 = 0,
    fn new(pci_dev:pci.PciDev) Rtl8139 {
        return .{.pd = pci_dev}; 
    }
};

const console = @import("../../console.zig");
var dev:Rtl8139 = undefined;
pub fn init() void {
    const rtl = pci.findDev(rtl8139_vendro, rtl8139_device) orelse {
        console.print("rtl8139 dev not found\n", .{}); 
        return;
    }; 

    dev = Rtl8139.new(rtl);
    const bars = dev.pd.getBar();
    for (0..bars.len) |i| {
        const b = bars[i] orelse continue;
        dev.bar_addr = b.addr;
        dev.bar_len = b.len;
    }
    const ptr:*u48 = @ptrFromInt(dev.bar_addr);
    const mac = ptr.*;
    console.print("mac: {x}:{x}:{x}:{x}:{x}:{x}\n", 
        .{@as(u8, @truncate(mac & 0xff)),
        @as(u8, @truncate((mac >> 8) & 0xff)),
        @as(u8, @truncate((mac >> 16) & 0xff)),
        @as(u8, @truncate((mac >> 24) & 0xff)),
        @as(u8, @truncate((mac >> 32) & 0xff)),
        @as(u8, @truncate((mac >> 40) & 0xff))});
    dev.pd.enableBusMastering();

}
