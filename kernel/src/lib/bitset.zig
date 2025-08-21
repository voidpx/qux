const std = @import("std");
pub fn bitSetFrom(bits:[]u8) std.DynamicBitSetUnmanaged {
    std.debug.assert(bits.len % @sizeOf(usize) == 0);
    return .{
        .bit_length = bits.len * 8,
        .masks = @ptrCast(@alignCast(bits.ptr)),
        };
}

pub fn findFirstUnSet(set:*const std.DynamicBitSetUnmanaged) ?usize {
    var offset: usize = 0;
    var mask = set.masks;
    const a1 = ~@as(std.DynamicBitSetUnmanaged.MaskInt, 0);
    while (offset < set.bit_length) {
        if (mask[0] != a1) break;
        mask += 1;
        offset += @bitSizeOf(std.DynamicBitSetUnmanaged.MaskInt);
    } else return null;
    const r = ~mask[0];
    return offset + @ctz(r);
}


