const ata = @import("driver/ata.zig");
const ext2 = @import("driver/fs/ext2.zig");
pub fn init() void {
    ata.init();
    ext2.init(); 
}

