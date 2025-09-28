const task = @import("../task.zig");
const lock = @import("../lock.zig");
const alloc = @import("../mem.zig").allocator;
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

    fn getSrcPort(self:*@This()) u16 {
        return @byteSwap(self.sport);
    }

    fn getDstPort(self:*@This()) u16 {
        return @byteSwap(self.dport);
    }

    fn getLength(self:*@This()) u16 {
        return @byteSwap(self.length);
    }

    fn getSum(self:*@This()) u16 {
        return @byteSwap(self.csum);
    }

    fn setSrcPort(self:*@This(), port:u16) void {
        self.sport = @byteSwap(port);
    }
    fn setDstPort(self:*@This(), port:u16) void {
        self.dport = @byteSwap(port);
    }
    fn setSum(self:*@This(), sum:u16) void {
        self.csum = @byteSwap(sum);
    }
    fn setLength(self:*@This(), len:u16) void {
        self.length = @byteSwap(len);
    }
};

const SockMap = std.AutoHashMap(net.SockAddr, *net.Sock);
var sock_map:SockMap = undefined;

const udp_sk_ops:net.SockOps = .{
    .recv = &udpReceive,
    .recv_from = &udpReceiveFrom,
    .send = &udpSend,
    .send_to = &udpSendTo,
    .bind = &udpBind,
    .listen = &udpListen,
    .connect = &udpConnect,
    .accept = &udpAccept,
    .release = &udpReleaseSock,
};

const proto_udp:net.ProtoFamily = .{.new_sock = undefined};


fn newUdpSk() !*net.Sock {
    const sk = try alloc.create(net.Sock);
    sk.* = .{};
    sk.ops = &udp_sk_ops;
    return sk;
}

fn udpReceiveFrom(sk:*net.Sock, buf: []u8, addr:?*net.SockAddr) ![]u8 {
    const l = lock.cli();
    defer lock.sti(l);
    while (true) {
        const p = sk.rq.peek() orelse {
            task.wait(&sk.rwq);
            continue;
        };
        const tdata = p.getTransPacket();
        const data = tdata[@sizeOf(UdpHdr)..];
        const off = @min(sk.rq.read_pos, data.len);
        const len = @min(buf.len, data.len - off);
        const ret = buf[0..len];
        @memcpy(ret, data[off..len]);
        sk.rq.read_pos += len;
        if (addr) |a| {
            const iph = p.getIpV4Hdr();
            const uph:*UdpHdr = @ptrCast(tdata.ptr);
            a.family = 0;
            a.addr = iph.getSrcAddr();
            a.port = uph.getSrcPort();
            @memset(&a.pad, 0);
        }
        if (sk.rq.read_pos >= data.len) {
            const h =sk.rq.dequeue();
            sk.rq.read_pos = 0;
            h.?.free();
        }
        return ret;
    }
}
fn udpReceive(sk:*net.Sock, buf: []u8) ![]u8 {
    return try udpReceiveFrom(sk, buf, null);
}

fn ensureBind(sk:*net.Sock) !void {
    if (sk.src_addr) |_| return;
    try udpBind(sk, &.{
        .port = 1024,
    });
}

fn udpSendTo(sk:*net.Sock, buf:[]const u8, to:?*const net.SockAddr) !usize {
    const raddr = to orelse return error.NullRemoteAddress; 
    const addr:net.SockAddr = .{.addr = @byteSwap(raddr.addr), .port = @byteSwap(raddr.port)};
    try ensureBind(sk);
    const ulen:u16 = @intCast(@sizeOf(UdpHdr) + buf.len);
    const out = try ip.newPacket(ulen); 
    defer out.free();
    const iph = out.getIpV4Hdr();
    iph.setSrcAddr(sk.src_addr.?.addr);
    iph.setDstAddr(addr.addr);
    iph.setTotalLen(ulen + @sizeOf(net.IpV4Hdr));
    iph.proto = @intFromEnum(net.TransProto.UDP);
    const tdata = out.getTransPacket();
    const uh:*UdpHdr = @ptrCast(tdata.ptr);
    uh.setSrcPort(sk.src_addr.?.port);
    uh.setDstPort(addr.port);
    uh.setLength(ulen);
    const payload = tdata[@sizeOf(UdpHdr)..]; 
    @memcpy(payload, buf);
    try ip.ipSend(out, &calcUdpSum);
    return buf.len;

}
fn udpSend(sk:*net.Sock, buf:[]const u8) !usize {
    try ensureBind(sk);
    if (sk.dst_addr == null) return error.UdpNotConnected;
    return try udpSendTo(sk, buf, &sk.dst_addr.?);
}

fn udpBind(sk:*net.Sock, addr:*const net.SockAddr) !void {
    sk.src_addr = net.SockAddr{
        .family = 0,
        .port = @byteSwap(addr.port),
        .addr = @byteSwap(net.net_dev.ipv4_addr),
    };
    try sock_map.put(sk.src_addr.?, sk);
}

fn udpListen(_:*net.Sock) !void {
    return error.InvalidSockForListen;
}

fn udpAccept(_:*net.Sock) !*net.Sock {
    return error.InvalidSockForAccept;
}

fn udpConnect(sk:*net.Sock, addr:*const net.SockAddr) !void {
    sk.dst_addr = net.SockAddr{
        .family = 0,
        .port = addr.port,
        .addr = @byteSwap(net.net_dev.ipv4_addr),
    };
}

fn udpReleaseSock(sk:*net.Sock) void {
    if (sk.src_addr) |a| {
        _ = sock_map.remove(a);
    }
    alloc.destroy(sk);
}

pub fn init() void {
    ip.registerTransProto(net.TransProto.UDP, &nr) catch unreachable; 
    sock_map = SockMap.init(alloc);

    //@import("../kthread.zig").createKThread("test_udp", &testUdp, null);
}

fn testUdp(_:?*anyopaque) u16 {
    const sk = newUdpSk() catch unreachable;
    udpBind(sk, &.{.port=90}) catch unreachable;
    const buf:[]u8 = alloc.alloc(u8, 1024) catch unreachable;
    defer alloc.free(buf);
    while (true) {
        var addr:net.SockAddr = .{};
        const r = sk.ops.recv_from(sk, buf, &addr) catch unreachable;
        _=sk.ops.send_to(sk, r, &addr) catch unreachable;

    }
}

fn calcUdpSum(p_sum:u16, pkt:*net.Packet) void {
    const data = pkt.getTransPacket();
    const uhdr:*UdpHdr = @ptrCast(data.ptr);
    uhdr.csum = 0;
    var sum = ip.calcSum(data);
    sum = ip.addToSumU16(sum, ~p_sum);
    uhdr.setSum(sum);
}

const icmp = @import("icmp.zig");
fn udpRecv(_:*net.NetReceiver, pkt:*net.Packet) !void {
    const l = lock.cli();
    defer lock.sti(l);
    //console.print("udp packet:{s}\n", .{std.fmt.fmtSliceHexLower(pkt.getRaw())});
    const iphdr:*net.IpV4Hdr = pkt.getIpV4Hdr();
    const uhdr:*UdpHdr = @ptrCast(@as([*]u8, @ptrCast(iphdr)) + @sizeOf(net.IpV4Hdr));
    const addr:net.SockAddr = .{
        .addr = iphdr.getDstAddr(),
        .port = uhdr.getDstPort(),
    };

    const sk = sock_map.get(addr) orelse {
        defer pkt.free();
        try icmp.icmpReplyPortUnreachable(pkt, iphdr.getDstAddr());
        return;
    };
    sk.rq.enqueue(pkt);
    task.wakeup(&sk.rwq);
}

