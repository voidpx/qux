const ata = @import("driver/block/ata.zig");
const ext2 = @import("driver/fs/ext2.zig");
const rtl8139 = @import("driver/net/rtl8139.zig");
pub fn init() void {
    ata.init();
    ext2.init(); 
    rtl8139.init();
}

