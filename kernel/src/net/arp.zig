const net = @import("net.zig");
const std = @import("std");
const console = @import("../console.zig");
var recv:net.NetReceiver = .{.recv = &arpRecv};

const ArpPacket = extern struct {
    hwt:u16 align(1),
    ptt:u16 align(1),
    hlen:u8 align(1) = 6,
    plen:u8 align(1) = 4,
    op:u16 align(1),
    sh_addr:[6]u8,
    sp_addr:u32 align(1),
    th_addr:[6]u8,
    tp_addr:u32 align(1),
    fn getHwType(self:*@This()) u16 {
        return @byteSwap(self.hwt);
    }
    fn getPtType(self:*@This()) u16 {
        return @byteSwap(self.ptt);
    }
    fn getOp(self:*@This()) u16 {
        return @byteSwap(self.op);
    }
};

pub fn init() void {
    net.registerNetProtoHandler(net.NetProto.ARP, &recv) catch unreachable;

    const repp:*net.Packet = net.Packet.new(60) catch unreachable;
    defer repp.free();
    const rep:*ArpPacket = @ptrCast(repp.getNetPacket().ptr);
    rep.hwt = @byteSwap(@as(u16, 1));
    rep.ptt = @byteSwap(@as(u16, 0x0800));
    rep.hlen = 6;
    rep.plen = 4;
    rep.op = 0x0100;
    const smac = @byteSwap(net.net_dev.mac);
    @memcpy(&rep.sh_addr, @as([*]const u8, @ptrCast(&smac)));
    rep.sp_addr = net.net_dev.ipv4_addr;
    const bcast:u48 = 0;
    @memcpy(&rep.th_addr, @as([*]const u8, @ptrCast(&bcast)));
    rep.tp_addr = 0x20a14ac;
    
    repp.setNetProto(net.NetProto.ARP);
    //repp.setDstMac(@byteSwap(@as(*align(1) u48, @ptrCast(&ap.sh_addr)).*));
    repp.setDstMac(0xffffffffffff);
    
    net.xmitPacket(repp) catch unreachable;
}

fn arpRecv(nr:*net.NetReceiver, pkt:*net.Packet) !void {
    _=&nr;
    defer pkt.free();
    const pk = pkt.getNetPacket();
    const ap:*ArpPacket = @ptrCast(@alignCast(pk.ptr));
    //console.print("arp packet received: size:{}\n{s}\n", .{pk.len, std.fmt.fmtSliceHexLower(pk)});
    
    const repp:*net.Packet = try net.Packet.new(60);
    defer repp.free();
    const rep:*ArpPacket = @ptrCast(repp.getNetPacket().ptr);
    rep.hwt = @byteSwap(@as(u16, 1));
    rep.ptt = @byteSwap(@as(u16, 0x0800));
    rep.hlen = 6;
    rep.plen = 4;
    rep.op = 0x0200; // response
    const smac = @byteSwap(net.net_dev.mac);
    @memcpy(&rep.sh_addr, @as([*]const u8, @ptrCast(&smac)));
    rep.sp_addr = net.net_dev.ipv4_addr;
    rep.th_addr = ap.sh_addr;
    rep.tp_addr = ap.sp_addr;
    
    repp.setNetProto(net.NetProto.ARP);
    repp.setDstMac(@byteSwap(@as(*align(1) u48, @ptrCast(&ap.sh_addr)).*));
    
    try net.xmitPacket(repp);
    
}

/// resolve the dest mac and send
pub fn arpSend(dev:*net.NetDev, pkt:*net.Packet, send:*const fn(pkt:*net.Packet) anyerror!void) !void {
    _=&dev;
    //TODO: implement arp query
    pkt.setDstMac(0x3a64509fee2f);
    try send(pkt);    
}

