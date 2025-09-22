const ip = @import("ip.zig");
const net = @import("net.zig");
const std = @import("std");
var icmp_recv:net.NetReceiver = .{.recv = &icmpRecv};
const console = @import("../console.zig");

const ICMPHdr = extern struct {
    type:u8 align(1),
    code:u8 align(1),
    csum:u16 align(1),
    //union
    id:u16 align(1),
    seq:u16 align(1)
};

pub fn init() void {
    ip.registerTransProto(net.TransProto.ICMP, &icmp_recv) catch unreachable; 
}

pub fn icmpRecv(nr:*net.NetReceiver, pkt:*net.Packet) !void {
    defer pkt.free();
    _=&nr;
    _=&pkt;
    console.print("icmp packet received:{s}\n", .{std.fmt.fmtSliceHexLower(pkt.getRaw())});
    const iphdr:[*]u8 = @ptrCast(pkt.getIpV4Hdr());
    const icmp_hdr:*ICMPHdr = @ptrCast(iphdr + @sizeOf(net.IpV4Hdr));
    //console.print("iphdr:{s}\n", .{std.fmt.fmtSliceHexLower(iphdr[0..@sizeOf(net.IpV4Hdr)])});
    try icmpReply(pkt.getIpV4Hdr(), icmp_hdr, pkt); 

}

fn icmpReply(iph:*net.IpV4Hdr, hdr:*ICMPHdr, pkt:*net.Packet) !void {
    switch (hdr.type) {
        8 => {
            try icmpEchoReply(iph, hdr, pkt);
        },
        else =>{

            console.print("unknown icmp type:{}\n", .{hdr.type});
        }
    }
}

fn icmpEchoReply(iph:*net.IpV4Hdr, hdr:*ICMPHdr, _:*net.Packet) !void {
    const plen = iph.getTotalLen() - @sizeOf(net.IpV4Hdr);
    const out = try ip.newPacket(plen);
    defer out.free();
    const out_hdr = out.getIpV4Hdr();
    out_hdr.* = iph.*;

    const out_icmp_hdr:*ICMPHdr = @ptrCast(@as([*]u8, @ptrCast(out_hdr)) + @sizeOf(net.IpV4Hdr));
    const data:[*]u8 = @ptrCast(hdr);
    const out_data:[*]u8 = @ptrCast(out_icmp_hdr);
    @memcpy(out_data[0..plen], data[0..plen]);
    out_icmp_hdr.type = 0; // reply
    out_icmp_hdr.csum = 0;
    const sum = ip.calcSum(out_data[0..plen]);
    out_icmp_hdr.csum = @byteSwap(sum);
    out_hdr.setDstAddr(iph.getSrcAddr());
    out_hdr.proto = @intFromEnum(net.TransProto.ICMP);
    try ip.ipSend(out, null);
}

