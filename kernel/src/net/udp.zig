const std = @import("std");
const console = @import("../console.zig");
const ip = @import("ip.zig");
const net = @import("net.zig");
var nr:net.NetReceiver = .{.recv = &udpRecv};
const UdpHdr = extern struct {
    sport:u16 align(1),
    dport:u16 align(1),
    length:u16 align(1),
    csum:u16 align(1),
};

pub fn init() void {
    ip.registerTransProto(net.TransProto.UDP, &nr) catch unreachable; 
}

fn calcUdpSum(pkt:*net.Packet) void {
    const iphdr:*net.IpV4Hdr = pkt.getIpV4Hdr();
    const uhdr:*UdpHdr = @ptrCast(@as([*]u8, @ptrCast(iphdr)) + @sizeOf(net.IpV4Hdr));
    uhdr.csum = 0;
    const len = @byteSwap(uhdr.length);
    var sum = ip.calcSum(@as([*]u8, @ptrCast(uhdr))[0..len]);
    sum = ip.addToSum(sum, @as([*]u8, @ptrCast(&iphdr.src_addr))[0..@sizeOf(@TypeOf(iphdr.src_addr))]); 
    sum = ip.addToSum(sum, @as([*]u8, @ptrCast(&iphdr.dst_addr))[0..@sizeOf(@TypeOf(iphdr.dst_addr))]); 
    sum = ip.addToSumU16(sum, @as(u16, iphdr.proto));
    sum = ip.addToSumU16(sum, len);
    uhdr.csum = @byteSwap(sum);
}

fn udpRecv(_:*net.NetReceiver, pkt:*net.Packet) !void {
    defer pkt.free();
    console.print("udp packet:{s}\n", .{std.fmt.fmtSliceHexLower(pkt.getRaw())});
    const iphdr:*net.IpV4Hdr = pkt.getIpV4Hdr();
    const uhdr:*UdpHdr = @ptrCast(@as([*]u8, @ptrCast(iphdr)) + @sizeOf(net.IpV4Hdr));
    console.print("upp hdr: {any}\n", .{uhdr.*});
   
    // debug: echo back
    const new = try ip.newPacket(@byteSwap(uhdr.length));
    defer new.free();
    const new_iphdr = new.getIpV4Hdr();
    new_iphdr.* = .{.proto = @intFromEnum(net.TransProto.UDP)};
    new_iphdr.total_len = @byteSwap(@byteSwap(uhdr.length) + @sizeOf(net.IpV4Hdr));
    new_iphdr.dst_addr = iphdr.src_addr;
    new_iphdr.proto = iphdr.proto;
    
    const new_uhdr:*UdpHdr = @ptrCast(@as([*]u8, @ptrCast(new_iphdr)) + @sizeOf(net.IpV4Hdr));
    const new_data:[*]u8 = @ptrCast(new_uhdr);
    const src_data:[*]u8 = @ptrCast(uhdr);
    @memcpy(new_data[0..@byteSwap(uhdr.length)], src_data[0..@byteSwap(uhdr.length)]);
    new_uhdr.length = uhdr.length;
    new_uhdr.sport = uhdr.dport;
    new_uhdr.dport = uhdr.sport;
    try ip.ipSend(new, &calcUdpSum);
}

pub fn udpSend(msg:[]const u8) !void {
    _=&msg;
}
