const lock = @import("../lock.zig");
const std = @import("std");
const task = @import("../task.zig");
const ip = @import("ip.zig");
const net = @import("net.zig");
const console = @import("../console.zig");
const alloc = @import("../mem.zig").allocator;
const sk_ops = net.SockOps{
    .listen = &tcpListen,
    .bind = &tcpBind,
    .connect = &tcpConnect,
    .recv = &read, 
    .send = &write, 
    .release = &tcpReleaseSock};

const isn:u32 = 0x1234abcd;
const tcp_prot = net.ProtoFamily{.new_sock = &newTcpSock};

const ListenSockMap = std.AutoHashMap(net.SockAddr, *TcpSock);
const ConnSockMap = std.AutoHashMap(net.SockAddrPair, *TcpSock);
var listen_map:ListenSockMap = undefined;
var conn_map:ConnSockMap = undefined;

fn tcpListen(sk:*net.Sock) !void {
    const la = sk.src_addr orelse return error.TcpSockNotBound;
    toTcpSock(sk).state = .LISTEN;
    listen_map.put(la, toTcpSock(sk)) catch |e| {
        toTcpSock(sk).state = .CLOSED;
        return e;
    };
}

fn addressEqual(a1:*net.SockAddr, a2:*net.Sock) bool {
    return (a1.addr == a2.dst_addr and a1.port == a2.port);
}

fn tcpAccept(sk:*net.Sock) !*net.Sock {
    const tsk = toTcpSock(sk);
    const l = lock.cli();
    defer lock.sti(l);
    while (true) {
        for (0..tsk.conns.items.len) |i| {
            const s = tsk.conns.items[i];
            if (s.state == .ESTABLISHED) {
                _=tsk.conns.orderedRemove(i);
                return &s.sk;
            }
        }
        task.wait(&sk.rwq);
    }
}

fn tcpBind(sk:*net.Sock, addr:*const net.SockAddr) !void {
    //TODO: check already bound addresses

    //sk.src_addr = addr.*;
    // bind on the dummy address
    sk.src_addr = net.SockAddr{
        .family = 0,
        .port = @byteSwap(addr.port),
        .addr = @byteSwap(net.net_dev.ipv4_addr),
    };
}

fn tcpConnect(sk:*net.Sock, addr:*const net.SockAddr) !void {
    // TODO: implement connect 
    sk.src_addr = .{
        .addr = @byteSwap(addr.addr),
        .port = @byteSwap(addr.port),
    };
}

fn newTcpSock() !*net.Sock {
    const sk = try TcpSock.new();
    sk.sk.ops = &tcp_sk_ops;
    return &sk.sk;
}

fn tcpReleaseSock(sk:*net.Sock) void {
    const tsk:*TcpSock = toTcpSock(sk);
    if (tsk.state == .LISTEN) {
        _ = listen_map.remove(tsk.sk.src_addr.?);
    } else {
        _=conn_map.remove(.{.src = tsk.sk.src_addr.?, .dst = tsk.sk.dst_addr.?});
    }
    tsk.free();
}

const tcp_sk_ops:net.SockOps = .{
    .bind = &tcpBind,
    .listen = &tcpListen,
    .accept = &tcpAccept,
    .connect = &tcpConnect,
    .send = &tcpSend,
    .send_to = &tcpSendTo,
    .recv = &tcpReceive,
    .recv_from = &tcpReceiveFrom,
    .release = &tcpReleaseSock
};

inline fn checkConnected(sk:*TcpSock) !void {
    if (sk.state != .ESTABLISHED) return error.TcpNotConnected;
}

fn tcpSendTo(sk:*net.Sock, buf:[]const u8, _:?*const net.SockAddr) anyerror!usize {
    return try tcpSend(sk, buf);
}

fn tcpSend(sk:*net.Sock, buf:[]const u8) anyerror!usize {
    const tsk = toTcpSock(sk);
    try checkConnected(tsk);
    const out = try ip.newPacket(@intCast(@sizeOf(TcpHdr) + buf.len)); 
    defer out.free();
    sendPrepare(tsk, &sk.dst_addr.?, out);
    const tdata = out.getTransPacket();
    const th:*TcpHdr = @ptrCast(tdata.ptr);
    th.setACK(true);
    th.setHdrLen(@sizeOf(TcpHdr));
    const payload = tdata[@sizeOf(TcpHdr)..]; 
    @memcpy(payload, buf);
    try ip.ipSend(out, &calcTcpSum);
    tsk.seq = @addWithOverflow(tsk.seq, @as(u32, @truncate(buf.len)))[0];
    return buf.len;
}

fn tcpReceiveFrom(sk:*net.Sock, buf:[]u8, _:?*net.SockAddr) anyerror![]u8 {
    return try tcpReceive(sk, buf);
}

fn tcpReceive(sk:*net.Sock, buf:[]u8) anyerror![]u8 {
    const tsk = toTcpSock(sk);
    const l = lock.cli();
    defer lock.sti(l);
    while (true) {
        try checkConnected(tsk);
        const p = sk.rq.peek() orelse {
            task.wait(&sk.rwq);
            continue;
        };
        const tdata = p.getTransPacket();
        const data = tdata[@sizeOf(TcpHdr)..];
        const off = @min(sk.rq.read_pos, data.len);
        const len = @min(buf.len, data.len - off);
        const ret = buf[0..len];
        @memcpy(ret, data[off..len]);
        sk.rq.read_pos += len;
        if (sk.rq.read_pos >= data.len) {
            const h =sk.rq.dequeue();
            sk.rq.read_pos = 0;
            h.?.free();
        }
        return ret;
    }
}

/// TODO: split this into listening socket and connection socket
const TcpSock = struct {
    sk:net.Sock = .{},
    seq:u32 = 0,
    ack:u32 = 0,
    state:TcpState = .CLOSED,
    conns:std.ArrayList(*TcpSock) = undefined,
    fn new() !*TcpSock {
        const p = try alloc.create(@This());
        p.* = .{};
        p.conns = std.ArrayList(*TcpSock).init(alloc);
        return p;
    }
    fn free(this:*@This()) void {
        this.conns.deinit();
        return alloc.destroy(this);
    }
};

const TcpHdr = extern struct {
    sport:u16 align(1) = 0,
    dport:u16 align(1) = 0,
    seq:u32 align(1) = 0,
    ack:u32 align(1) = 0,
    hlen_res:u8 align(1) = 0b01010000, // no options by default
    flags:u8 align(1) = 0,
    win_size:u16 align(1) = @byteSwap(@as(u16, 64240)),
    csum:u16 align(1) = 0,
    urg:u16 align(1) = 0,
    fn setSrcPort(self:*@This(), sp:u16) void {
         self.sport = @byteSwap(sp);
    }
    fn setDstPort(self:*@This(), dp:u16) void {
         self.dport = @byteSwap(dp);
    }
    fn setSum(self:*@This(), sum:u16) void {
         self.csum = @byteSwap(sum);
    }
    fn setSeq(self:*@This(), s:u32) void {
         self.seq = @byteSwap(s);
    }
    fn setAck(self:*@This(), a:u32) void {
         self.ack = @byteSwap(a);
    }
    fn setWinSize(self:*@This(), ws:u16) u16 {
         self.win_size = @byteSwap(ws);
    }
    fn setHdrLen(self:*@This(), nbytes:u8) void {
        const nw = nbytes/4;
         self.hlen_res = (nw & 0xf) << 4;
    }


    fn getSrcPort(self:*@This()) u16 {
        return @byteSwap(self.sport);
    }
    fn getDstPort(self:*@This()) u16 {
        return @byteSwap(self.dport);
    }
    fn getSum(self:*@This()) u16 {
        return @byteSwap(self.csum);
    }
    fn getSeq(self:*@This()) u32 {
        return @byteSwap(self.seq);
    }
    fn getAck(self:*@This()) u32 {
        return @byteSwap(self.ack);
    }
    fn getHdrLen(self:*@This()) u8 {
        return (self.hlen_res>>4) * 4;
    }
    fn getWinSize(self:*@This()) u16 {
        return @byteSwap(self.win_size);
    }

    fn isCWR(self:*@This()) bool {
        return self.getFlag(7);
    }
    fn isECE(self:*@This()) bool {
        return self.getFlag(6);
    }
    fn isURG(self:*@This()) bool {
        return self.getFlag(5);
    }
    fn isACK(self:*@This()) bool {
        return self.getFlag(4);
    }
    fn isPSH(self:*@This()) bool {
        return self.getFlag(3);
    }
    fn isRST(self:*@This()) bool {
        return self.getFlag(2);
    }
    fn isSYN(self:*@This()) bool {
        return self.getFlag(1);
    }
    fn isFIN(self:*@This()) bool {
        return self.getFlag(0);
    }

    fn getFlag(self:*@This(), shift:u3) bool {
        return self.flags & (@as(u8, 1) << shift) > 0;
    }
    fn setFlag(self:*@This(), shift:u3, set:bool) void {
        if (set) {
            self.flags |= @as(u8, 1) << shift;
        } else {
            self.flags &= ~(@as(u8, 1) << shift);
        }
    }
    fn setCWR(self:*@This(), f:bool) void {
        self.setFlag(7, f); 
    }
    fn setECE(self:*@This(), f:bool) void {
        self.setFlag(6, f); 
    }
    fn setURG(self:*@This(), f:bool) void {
        self.setFlag(5, f); 
    }
    fn setACK(self:*@This(), f:bool) void {
        self.setFlag(4, f); 
    }
    fn setPSH(self:*@This(), f:bool) void {
        self.setFlag(3, f); 
    }
    fn setRST(self:*@This(), f:bool) void {
        self.setFlag(2, f); 
    }
    fn setSYN(self:*@This(), f:bool) void {
        self.setFlag(1, f); 
    }
    fn setFIN(self:*@This(), f:bool) void {
        self.setFlag(0, f); 
    }

};

const TcpState = enum(u8) {
    CLOSED,
    LISTEN,
    SYN_SENT,
    SYN_RCVD,
    ESTABLISHED,
    CLOSE_WAIT,
    LAST_ACK,
    FIN_WAIT1,
    FIN_WAIT2,
    CLOSING,
    TIME_WAIT,
};

var recv:net.NetReceiver = .{.ctx = null, .recv = &handleTcpRecv};
const kthread = @import("../kthread.zig");
pub fn init() void {
    ip.registerTransProto(net.TransProto.TCP, &recv) catch unreachable;
    net.registerProtoFamily(net.Proto.SOCK_STREAM, &tcp_prot) catch unreachable;
    listen_map = ListenSockMap.init(alloc);
    conn_map = ConnSockMap.init(alloc);
    net.registerProtoFamily(net.Proto.SOCK_STREAM, &tcp_prot) catch unreachable;
    
    //kthread.createKThread("test_tcp", &testTcp, null);
}

fn testTcpEcho(a:?*anyopaque) u16 {
    const sk:*TcpSock = @alignCast(@ptrCast(a.?));
    const buf:[]u8 = alloc.alloc(u8, 1024) catch unreachable;
    defer alloc.free(buf);
    while (true) {
        const d = sk.sk.ops.recv(&sk.sk, buf) catch |e| {
            console.print("error recv tcp packet: {}\n", .{e}); 
            break;
        };
        //console.print("received tcp pkt:{s}\n", .{d});
        _=sk.sk.ops.send(&sk.sk, d) catch |e| {
            console.print("error sending tcp packet: {}\n", .{e}); 
            break;
        };
    }
    return 0;
}

fn testTcp(_:?*anyopaque) u16 {
    const sk = newTcpSock() catch unreachable; 
    const addr:net.SockAddr = .{
        .port = 80,
    };
    tcpBind(sk, &addr) catch unreachable;
    tcpListen(sk) catch unreachable;
    while (true) {
        const a = tcpAccept(sk) catch unreachable;
        kthread.createKThread("test_tcp_echo", &testTcpEcho, a);
        //task.schedule();
        //asm volatile("sti; hlt");
    }
    
}

const MSS:u16 = 1460;

fn write(sk:*net.Sock, buf:[]const u8) !usize {
    
    _=&sk;
    _=&buf;
}

fn read(sk:*net.Sock, buf:[]u8) ![]u8 {
    _=&sk;
    _=&buf;
}

fn calcTcpSum(p_sum:u16, pkt:*net.Packet) void {
    const data:[]u8 = pkt.getTransPacket();
    const thdr:*TcpHdr = @ptrCast(data.ptr);
    thdr.csum = 0;
    var sum = ip.calcSum(data);
    sum = ip.addToSumU16(sum, ~p_sum);
    thdr.setSum(sum);
}

inline fn getTcpPktLen(th:*TcpHdr, in:*net.Packet) u32 {
    if (th.isSYN) {
        return 1;
    }
    const th_len = th.getHdrLen() * 4;
    return in.getIpV4Hdr().getTotalLen() - th_len;
}

fn sendPrepare0(src_addr:*const net.SockAddr, dst_addr:*const net.SockAddr, out:*net.Packet) void {
    const out_iph = out.getIpV4Hdr();
    out_iph.setIHL(20);
    const raw = out.getRaw();
    const total_len = raw.ptr + raw.len - @as([*]u8, @ptrCast(out_iph));
    out_iph.setTotalLen(@intCast(total_len));
    const tcp_data = out.getTransPacket();
    const out_th:*TcpHdr = @ptrCast(tcp_data.ptr);
    out_th.* = .{}; // set defaults
    out_th.setSrcPort(src_addr.port);
    out_th.setDstPort(dst_addr.port);

    out_iph.setDstAddr(dst_addr.addr);
    out_iph.proto = @intFromEnum(net.TransProto.TCP);
}
fn sendPrepare(sk:*TcpSock, dst_addr:*const net.SockAddr, out:*net.Packet) void {
    sendPrepare0(&sk.sk.src_addr.?, dst_addr, out);
    const out_th:*TcpHdr = @ptrCast(out.getTransPacket().ptr);
    out_th.setSeq(sk.seq);
    out_th.setAck(sk.ack);
}

fn sendRST(laddr:*const net.SockAddr, raddr:*const net.SockAddr, th:*TcpHdr) !void {
    const out = try ip.newPacket(@sizeOf(TcpHdr));
    defer out.free();
    const out_th:*TcpHdr = @ptrCast(out.getTransPacket().ptr);
    sendPrepare0(laddr, raddr, out);
    out_th.setSeq(0x1234abcd);
    out_th.setAck(th.getSeq() + 1);
    out_th.setACK(true);
    out_th.setRST(true);
    out_th.setHdrLen(@sizeOf(TcpHdr));
    try ip.ipSend(out, &calcTcpSum);
}

inline fn toTcpSock(sk:*net.Sock) *TcpSock {
    var p:[*]u8 = @ptrCast(sk);
    p -= @offsetOf(TcpSock, "sk");
    return @alignCast(@ptrCast(p));
}

fn getAddrPair(pkt:*net.Packet) net.SockAddrPair {
    const th:*TcpHdr = @ptrCast(pkt.getTransPacket().ptr);
    const iph:*net.IpV4Hdr = pkt.getIpV4Hdr();
    return .{
        .src = .{
            .addr = iph.getSrcAddr(),
            .port = th.getSrcPort(),
        },
        .dst = .{
            .addr = iph.getDstAddr(),
            .port = th.getDstPort(),
        },

    };
}

fn recvSYN(pkt:*net.Packet, ap:*const net.SockAddrPair) !void {
    const th:*TcpHdr = @ptrCast(pkt.getTransPacket().ptr);
    const lts = listen_map.get(ap.dst) orelse {
        try sendRST(&ap.dst, &ap.src, th);
        return;
    };
    if (lts.state != .LISTEN) {
        try sendRST(&ap.dst, &ap.src, th);
        return;
    }
    const len = @sizeOf(TcpHdr) + 4;
    const out = try ip.newPacket(len); // MSS option
    defer out.free();
    const new_sk = toTcpSock(try newTcpSock());
    new_sk.sk.src_addr = ap.dst;
    new_sk.sk.dst_addr = ap.src;
    new_sk.seq = isn;
    new_sk.ack = th.getSeq() + 1;
    sendPrepare(new_sk, &ap.src, out);
    const out_th:*TcpHdr = @ptrCast(out.getTransPacket().ptr);
    const opt_mss:[*]u8 = @as([*]u8, @ptrCast(out_th)) + @sizeOf(TcpHdr); 
    opt_mss[0] = 2; // MSS kind
    opt_mss[1] = 4; // length including kind, rest 2 bytes is MSS
    @as(*align(1) u16, @ptrCast(opt_mss+2)).* = @byteSwap(MSS);

    out_th.setHdrLen(len);
    out_th.setSYN(true);
    out_th.setACK(true);
    
    ip.ipSend(out, &calcTcpSum) catch |e| {
        new_sk.sk.ops.release(&new_sk.sk);
        return e;
    };
    new_sk.seq += 1; // SYN+ACK takes up 1 byte
    new_sk.state = .SYN_RCVD;
    conn_map.put(.{.src = ap.dst, .dst = ap.src}, new_sk) catch |e| {
        new_sk.sk.ops.release(&new_sk.sk);
        return e;
    };
}

fn sendACK(sk:*TcpSock, pkt:*net.Packet, fin:bool) !void {
    const out = try ip.newPacket(@sizeOf(TcpHdr));
    defer out.free();
    const ap = getAddrPair(pkt);
    sendPrepare(sk, &ap.src, out);
    const th:*TcpHdr = @ptrCast(out.getTransPacket().ptr);
    th.setHdrLen(@sizeOf(TcpHdr));
    th.setACK(true);
    if (fin) th.setFIN(true);
    try ip.ipSend(out, &calcTcpSum);
    if (fin) sk.seq = @addWithOverflow(sk.seq, 1)[0];
}

fn recvFIN(sk:*TcpSock, pkt:*net.Packet) !void {
    defer pkt.free();
    if (sk.state != .CLOSED) {
        sk.ack = @addWithOverflow(sk.ack, 1)[0];
        try sendACK(sk, pkt, false);
        try sendACK(sk, pkt, true);
        sk.state = .LAST_ACK;
    } else {
        console.print("FIN received in wrong state: {}\n", .{sk.state});
    }
    
}

fn handleRecv(ap:*const net.SockAddrPair, pkt:*net.Packet, th:*TcpHdr) !void {
    const l = lock.cli();
    defer lock.sti(l);
    const sk = conn_map.get(.{.src = ap.dst, .dst = ap.src});
    if (sk) |ts| {
        if (th.isFIN()) {
            try recvFIN(ts, pkt);
            return;
        }
        // connected or half open
        blk: switch (ts.state) {
            .SYN_RCVD => {
                if (th.isACK() and ts.seq == th.getAck()) {
                    // finished 3-way handshake
                    ts.state = .ESTABLISHED;
                    const lsk = listen_map.get(ts.sk.src_addr.?).?;
                    try lsk.conns.append(ts);
                    task.wakeup(&lsk.sk.rwq);
                } else {
                    console.print("SYN_RCVD state, but not an ACK: {any}, sk_seq:0x{x}, th_seq:0x{x}\n", .{th.*, ts.seq, th.getAck()});
                }
            },
            .ESTABLISHED => {
                const tdata = pkt.getTransPacket();
                const thlen = th.getHdrLen();
                const len = tdata.len - thlen;
                if (len == 0) {
                    if (th.isACK()) { // pure ack
                        // TODO: remove the packet waiting in the retransmission queue
                    }
                    break :blk;
                }
                const ack:u32 = @addWithOverflow(ts.ack, @as(u32, @truncate(len)))[0];
                if (ack != th.getSeq() + len) {
                    console.print("packet arrived out of order\n", .{});
                    break :blk;
                }
                ts.ack = ack;
                try sendACK(ts, pkt, false); 
                ts.sk.rq.enqueue(pkt);
                task.wakeup(&ts.sk.rwq);
                return;
            },
            .LAST_ACK => {
                if (th.getAck() == ts.seq) {
                    ts.state = .CLOSED;
                    console.print("FIN ACKED\n", .{});
                }
                _=conn_map.remove(.{.src = ap.dst, .dst = ap.src});
                task.wakeup(&ts.sk.rwq);
                task.wakeup(&ts.sk.wwq);
            },
            else => {
                console.print("tcp packet not handled\n", .{});
            }
        }
    } else {
        if (th.isSYN() and !th.isACK()) {
            try recvSYN(pkt, ap);
        } else {
        }
    }
    pkt.free();
}

fn handleTcpRecv(_:*net.NetReceiver, pkt:*net.Packet) !void {
    const th:*TcpHdr = @ptrCast(pkt.getTransPacket().ptr);
    const ap = getAddrPair(pkt);
    try handleRecv(&ap, pkt, th);
}

