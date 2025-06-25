/// block device
const io = @import("../io.zig");
const mem = @import("../mem.zig");
const std = @import("std");
pub const BlockDevice = struct {
    ctx:?*anyopaque = null,
    blk_size_shift:usize = 9,
    capacity:usize = 0,
    parts:[4]?*BlockDevice = [_]?*BlockDevice{null} ** 4,
    impl_read:*const fn(bdev:*BlockDevice, start:usize, buf:[]u8) io.IOError!void,
    impl_write:*const fn(bdev:*BlockDevice, start:usize, buf:[]u8) io.IOError!void,

    pub fn new(ctx:?*anyopaque, cap:usize, readfn: *const fn(bdev:*BlockDevice,
        start:usize, buf:[]u8) io.IOError!void,
        writefn: *const fn(bdev:*BlockDevice, 
        start:usize, buf:[]u8) io.IOError!void) BlockDevice {
        return BlockDevice{.ctx = ctx, .capacity = cap, .impl_read = readfn, .impl_write = writefn};
    }

    pub fn read(this:*@This(), boff:usize, buf:[]u8) io.IOError!usize {
        const start_blk = boff >> @truncate(this.blk_size_shift);
        if (start_blk >= this.capacity) return 0;
        var end_blk = (boff + buf.len + (@as(usize, 1) << @truncate(this.blk_size_shift)) - 1) >> @truncate(this.blk_size_shift);
        if (end_blk > this.capacity) end_blk = this.capacity;
        const nbytes = (end_blk - start_blk) << @truncate(this.blk_size_shift);
        const buf2 =mem.allocator.alloc(u8, nbytes) catch return io.IOError.ReadError;
        defer mem.allocator.free(buf2);
        try this.impl_read(this, start_blk, buf2);

        const off = boff & ((@as(usize, 1) << @truncate(this.blk_size_shift)) - 1);
        const len = @min(buf.len, nbytes - off);
        const dst:[*]u8 = @ptrCast(buf.ptr);
        @memcpy(dst, buf2[off..off+len]); 
        return  len;
    }
};
pub var block_device:BlockDevice = undefined;
pub fn init() void {

}


