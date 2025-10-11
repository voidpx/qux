const fs = @import("../fs.zig");
const task = @import("../task.zig");
const lock = @import("../lock.zig");
const ip = @import("ip.zig");
const net = @import("net.zig");
const std = @import("std");
const alloc = @import("../mem.zig").allocator;
var icmp_recv:net.NetReceiver = .{.recv = &icmpRecv};
const console = @import("../console.zig");

const SockMap = std.AutoHashMap(u16, *net.Sock);
var icmp_sk:SockMap = undefined;

pub const ICMPHdr = extern struct {
    type:u8 align(1),
    code:u8 align(1),
    csum:u16 align(1),
};

pub const ICMPEcho = extern struct {
    hdr:ICMPHdr,
    id:u16 align(1),
    seq:u16 align(1)
};

pub fn init() void {
    ip.registerTransProto(net.TransProto.ICMP, &icmp_recv) catch unreachable; 
    icmp_sk = SockMap.init(alloc);

}

pub fn addIcmpSk(id:u16, sk:*net.Sock) !void {
    if (icmp_sk.contains(id)) return error.IcmpIdUnavailable;
    try icmp_sk.put(id, sk);
}

pub fn removeIcmpSk(id:u16) void {
    _=icmp_sk.remove(id);
}

pub fn icmpRecv(nr:*net.NetReceiver, pkt:*net.Packet) !void {
    _=&nr;
    const l = lock.cli();
    defer lock.sti(l);
    errdefer pkt.free();
    //console.print("icmp packet received:{s}\n", .{std.fmt.fmtSliceHexLower(pkt.getRaw())});
    const iphdr:[*]u8 = @ptrCast(pkt.getIpV4Hdr());
    const icmp_hdr:*ICMPHdr = @ptrCast(iphdr + @sizeOf(net.IpV4Hdr));
    //console.print("iphdr:{s}\n", .{std.fmt.fmtSliceHexLower(iphdr[0..@sizeOf(net.IpV4Hdr)])});
    const it:ICMPType = @enumFromInt(icmp_hdr.type);
    switch (it) {
        .ECHO_REQ => {
            try icmpEchoReply(pkt.getIpV4Hdr(), icmp_hdr, pkt);
        },
        .ECHO_REP => {
            const icmp_echo:*ICMPEcho = @ptrCast(@as([*]u8, @ptrCast(icmp_hdr)));
            const sk = icmp_sk.get(@byteSwap(icmp_echo.id)) orelse return; // return error.NoListeningSock;
            sk.rq.enqueue(pkt); 
            net.notifyWaiters(sk, fs.PollIn);
            return;
        },
        else =>{
            console.print("unknown icmp type:{}\n", .{icmp_hdr.type});
        }
    }
    pkt.free();
}

pub const ICMPType = enum(u8) {
    ECHO_REQ = 8,
    ECHO_REP = 0,
    DST_UNREACH = 3,
    _
};

pub fn icmpReplyPortUnreachable(src:*net.Packet, dst:u32) !void {
    const np = src.getNetPacket(); 
    var out:*net.Packet = undefined;
    const len = @min(np.len, 516);
    out = try ip.newPacket(@intCast(@sizeOf(ICMPHdr) + 4 + len)); 
    defer out.free();
    const tdata = (out.getTransPacket().ptr + @sizeOf(ICMPHdr) + 4)[0..];
    @memcpy(tdata, np[0..len]);
    const ihdr:*ICMPHdr = @ptrCast(out.getTransPacket().ptr);
    ihdr.type = @intFromEnum(ICMPType.DST_UNREACH);
    ihdr.code = 3;
    const ptr:[*]u8 = @ptrCast(ihdr);
    ptr[4] = 0;
    ptr[5] = @intCast(np.len/4);
    ptr[6] = 0;
    ptr[7] = 0;
    try icmpSend(out, dst);
}

fn icmpSend(out:*net.Packet, addr:u32) !void {
    const td = out.getTransPacket();
    const ihdr:*ICMPHdr = @ptrCast(td.ptr);
    ihdr.csum = 0;
    const sum = ip.calcSum(td);
    ihdr.csum = @byteSwap(sum);
    const iph = out.getIpV4Hdr();
    iph.setDstAddr(addr);
    iph.proto = @intFromEnum(net.TransProto.ICMP);
    try ip.ipSend(out, null);

}

// ping reply
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
    out_icmp_hdr.type = @intFromEnum(ICMPType.ECHO_REP); // reply
    try icmpSend(out, iph.getSrcAddr());
}

