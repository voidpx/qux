const console = @import("../console.zig");
const net = @import("net.zig");
const std = @import("std");
const alloc = @import("../mem.zig").allocator;
const arp = @import("arp.zig");

const ProtoMap = std.AutoHashMap(net.TransProto, *net.NetReceiver);
var proto_map:ProtoMap = undefined;


const recv:net.NetReceiver = .{.ctx = null, .recv = &ipRecv};
pub fn init() void {
    net.registerNetProtoHandler(net.NetProto.IPV4, &recv) catch unreachable;
    proto_map = ProtoMap.init(alloc);
}

pub fn registerTransProto(proto: net.TransProto, nr: *net.NetReceiver) !void {
    try proto_map.put(proto, nr);
}

pub fn newPacket(payload_len:u16) !*net.Packet {
    const t_len = 20 + payload_len;
    const p = try net.newPacket(t_len);
    const hdr = p.getIpV4Hdr();
    hdr.ver_ihl = 0x45;
    hdr.ttl = 64;
    hdr.id = 0;
    hdr.total_len = t_len;
    hdr.dscp_enc = 0;
    hdr.flags_frag_off = @byteSwap(@as(u16, 0b010) << 13);
    return p;
}

fn ipRecv(nr:*net.NetReceiver, pkt:*net.Packet) !void {
    _=&nr;
    const hdr:*net.IpV4Hdr = pkt.getIpV4Hdr();
    var handler = proto_map.get(@enumFromInt(hdr.proto)) orelse {
        console.print("ipv4 packet unhandled:{s}\n", .{std.fmt.fmtSliceHexLower(pkt.getRaw())});
        console.print("proto: {}, src addr:0x{x}, dst addr:0x{x}\n", .{hdr.proto, hdr.getSrcAddr(), hdr.getDstAddr()});
        return;
    };
    try handler.recv(handler, pkt);
}

fn ipHdrSum(hdr:*net.IpV4Hdr) u16 {
    return calcSum(@as([*]u8, @ptrCast(hdr))[0..@sizeOf(net.IpV4Hdr)]);
}

pub fn addToSum(sum:u16, data:[]const u8) u16 {
    const sd = ~calcSum(data);
    return addToSumU16(sum, sd);
}

pub fn addToSumU16(sum:u16, add:u16) u16 {
    var s = ~sum;
    const v = @addWithOverflow(s, add);
    s = v[0];
    if (v[1] != 0) s += 1;
    return ~s;
}

pub fn calcSum(data:[]const u8) u16 {
    const len = (data.len + 1)/2;
    const rpad = data.len & 1 > 0;
    const d:[*]align(1) const u16 = @ptrCast(data.ptr);
    var sum:u16 = 0;
    for (0..len) |i| {
        var p:u16 = undefined;
        if (rpad and i == len-1) {
            p = @as(u16, data[i*2]) << 8;
        } else {
            p = @byteSwap(d[i]);
        }
        const v = @addWithOverflow(sum, p);
        sum = v[0];
        if (v[1] != 0) {
            sum += 1;
        }
    }
    return ~sum;

}
test "sum" {
    const d = [_]u8 {
0x00, 0x00, 0x00, 0x00, 0x42, 0xd5, 0x00, 0x01, 0x2c, 0x79, 0xcf, 0x68, 0x00, 0x00, 0x00, 0x00,  
0x29, 0xc8, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37};

    const sum = calcSum(&d);
    try std.testing.expect(sum == 0xd0ac);
}

pub fn ipSend(pkt:*net.Packet, callback:?*const fn(pkt:*net.Packet) void) !void {
    const hdr = pkt.getIpV4Hdr();
    pkt.setNetProto(net.NetProto.IPV4);
    hdr.setSrcAddr(@byteSwap(net.net_dev.ipv4_addr));
    hdr.csum = 0;
    hdr.csum = @byteSwap(ipHdrSum(hdr));
    if (callback) |c| c(pkt);
    try net.xmitPacket(pkt);
}

