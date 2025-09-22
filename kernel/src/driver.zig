const ata = @import("driver/ata.zig");
const ext2 = @import("driver/fs/ext2.zig");
const rtl8139 = @import("driver/net/rtl8139.zig");
const net = @import("net/net.zig");
const ipv4 = @import("net/ip.zig");
const arp = @import("net/arp.zig");
const icmp = @import("net/icmp.zig");
pub fn init() void {
    ata.init();
    ext2.init(); 
    rtl8139.init();
}

