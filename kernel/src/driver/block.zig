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
    impl_write:*const fn(bdev:*BlockDevice, start:usize, buf:[]const u8) io.IOError!void,

    pub fn new(ctx:?*anyopaque, cap:usize, readfn: *const fn(bdev:*BlockDevice,
        start:usize, buf:[]u8) io.IOError!void,
        writefn: *const fn(bdev:*BlockDevice, 
        start:usize, buf:[]const u8) io.IOError!void) BlockDevice {
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
    
    pub fn write(this:*@This(), boff:usize, buf:[]const u8) io.IOError!usize {
        if (buf.len == 0) return 0;
        var start_sec = boff >> @truncate(this.blk_size_shift);
        if (start_sec >= this.capacity) return 0;
        const sec_size = (@as(u64, 1) << @truncate(this.blk_size_shift));
        const start_off = boff & (sec_size - 1);
        const w_sec = (start_off + buf.len + (sec_size - 1)) >> @truncate(this.blk_size_shift);
        var end_sec = start_sec + w_sec;
        if (end_sec > this.capacity) end_sec = this.capacity;
        if (start_off == 0 and (buf.len & (sec_size - 1)) == 0) {
            // whole sectors starting at sector boundary => direct write
            const w_len = (end_sec-start_sec) << @truncate(this.blk_size_shift);
            try this.impl_write(this, start_sec, buf[0..w_len]);
            return w_len;
        }
        // read -> merge -> write
        var w_buf = buf;
        var ret:u64 = 0;
        if (start_off > 0) {
            const r_buf = mem.allocator.alloc(u8, sec_size) catch return io.IOError.WriteError;
            defer mem.allocator.free(r_buf);
            try this.impl_read(this, start_sec, r_buf);
            const frac = sec_size - start_off;
            const d_len = @min(frac, buf.len);
            @memcpy(r_buf[start_off..start_off+d_len], buf[0..d_len]); 
            try this.impl_write(this, start_sec, r_buf);
            ret = d_len;
            w_buf = buf[d_len..];
            start_sec += 1;
        }

        if (w_buf.len == 0) return ret;
        if (start_sec >= end_sec) return ret;
        const secs_bytes = (end_sec - start_sec) << @truncate(this.blk_size_shift);
        if (secs_bytes <= w_buf.len) {
            try this.impl_write(this, start_sec, w_buf[0..secs_bytes]);
            ret += secs_bytes;
            return ret; 
        }
        if (start_sec < end_sec - 1) {
            const f_sec_bytes = (end_sec-1 - start_sec) << @truncate(this.blk_size_shift);
            try this.impl_write(this, start_sec, w_buf[0..f_sec_bytes]);
            ret += f_sec_bytes;
            w_buf = w_buf[f_sec_bytes..];
            start_sec = end_sec - 1;
        }
        if (w_buf.len == 0) return ret;    
        //last partial sectors
        std.debug.assert(w_buf.len < sec_size);
        const r_buf = mem.allocator.alloc(u8, sec_size) catch return io.IOError.WriteError;
        defer mem.allocator.free(r_buf);
        try this.impl_read(this, start_sec, r_buf);
        @memcpy(r_buf[0..w_buf.len], w_buf); 
        try this.impl_write(this, start_sec, r_buf);
        ret += w_buf.len;
        return ret;
    }
};
pub var block_device:BlockDevice = undefined;
pub fn init() void {

}


