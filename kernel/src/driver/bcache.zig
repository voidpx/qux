const std = @import("std");
const time = @import("../time.zig");
const alloc = @import("../mem.zig").allocator;
const Block = struct {
    no:u64,
    last_access:i64 = 0,
    block:[]u8 = undefined, // always block size
    node:Node = undefined,
    fn new(bn:u64, blk_size:u64) !*Block {
        const n = try alloc.create(Block); 
        n.no = bn;
        n.block = (alloc.alloc(u8, blk_size) catch |err| {
            alloc.destroy(n);
            return err;
        });
        n.last_access = time.getTime().getAsNanoSeconds();
        return n;
    }
    fn drop(this:*@This()) void {
        alloc.free(this.block);
        alloc.destroy(this);

    }
};
fn bcomp(ba1:*anyopaque, ba2:*anyopaque) std.math.Order {
    const b1:*Block = @alignCast(@ptrCast(ba1));
    const b2:*Block = @alignCast(@ptrCast(ba2));
    if (b1.no < b2.no) return .lt;
    if (b1.no > b2.no) return .gt;
    return .eq;

}
const Cache = std.Treap(*anyopaque, bcomp);
const Node = Cache.Node;
const lock = @import("../lock.zig");
const blk = @import("block.zig");

pub const BCache = struct {
    cache:Cache,
    count:usize,
    bdev:*blk.BlockDevice,
    blk_size:u64,
    const SIZE = 1024;
    pub fn new(dev:*blk.BlockDevice, blk_size:u64) BCache {
        return .{.cache = .{}, .count = 0, .blk_size = blk_size, .bdev = dev};
    }

    pub fn getBlock(this:*@This(), bn:u64) ![]u8 {
        const l = lock.cli();
        defer lock.sti(l);
        const n = &Block{.no = bn};
        const e = this.cache.getEntryFor(@ptrCast(@constCast(n)));
        const node = e.node orelse blk: {
            var block = try Block.new(bn, this.blk_size);
            const len = this.bdev.read(bn * this.blk_size, block.block) catch |err| {
                block.drop();
                return err;
            }; 
            std.debug.assert(len == this.blk_size);
            var entry = this.cache.getEntryFor(block);
            std.debug.assert(e.node == null);
            entry.set(&block.node);
            break :blk &block.node; 
        };
        return @as(*Block, @alignCast(@ptrCast(node.key))).block;
    }

    pub fn drop(this:*@This()) void {
        const l = lock.cli();
        defer lock.sti(l);
        var it = this.cache.inorderIterator();
        while (it.next()) |n| {
            var e = this.cache.getEntryForExisting(n);
            e.set(null);
            var b:*Block = @alignCast(@ptrCast(n.key));
            b.drop();
        }
    }

};

