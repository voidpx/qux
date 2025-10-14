const std = @import("std");
const icmp = @import("icmp.zig");
const net = @import("net.zig");
const ip = @import("ip.zig");
const alloc = @import("../mem.zig").allocator;
const console = @import("../console.zig");
const lock = @import("../lock.zig");
const task = @import("../task.zig");

const raw_prot = net.ProtoFamily{.new_sock = &newRawSock};

const RawPriv = struct {
    proto:net.TransProto,
    priv:?*anyopaque,
};

const raw_sk_ops:net.SockOps = .{
    .bind = &bind,
    .listen = &listen,
    .accept = &accept,
    .connect = &connect,
    .send_to = &send_to,
    .send = &send,
    .recv_from = &recv_from,
    .recv = &recv,
    .release = &release,
    .poll = &net.sockPoll,
};

fn newRawSock(proto:u32) !*net.Sock {
    const s = try alloc.create(net.Sock);
    s.* = .{};
    const pri = try alloc.create(RawPriv);
    pri.proto = @enumFromInt(proto);
    pri.priv = null;
    s.priv = pri;
    s.ops = &raw_sk_ops;
    return s;
}

inline fn getProto(sk:*net.Sock) net.TransProto {
    return rawPriv(sk).proto;
}

inline fn rawPriv(sk:*net.Sock) *RawPriv {
    const priv:*RawPriv = @alignCast(@ptrCast(sk.priv.?));
    return priv;
}

fn bind(sk:*net.Sock, addr:*const net.SockAddr) anyerror!void {
    sk.src_addr = net.SockAddr{
        .family = 0,
        .port = @byteSwap(addr.port),
        .addr = @byteSwap(net.net_dev.ipv4_addr),
    };
}
fn listen(sk:*net.Sock) anyerror!void {
    _=&sk;
    return error.InvalidForRawProtocol;
}
fn accept(sk:*net.Sock) anyerror!*net.Sock {
    _=&sk;
    return error.InvalidForRawProtocol;
}
fn connect(sk:*net.Sock, addr:*const net.SockAddr) anyerror!void {
    _=&sk;
    _=&addr;
    return error.InvalidForRawProtocol;
}

fn addProtoSk(proto:net.TransProto, sk:*net.Sock, hdr:*icmp.ICMPHdr) !void {
    const l = lock.cli();
    defer lock.sti(l);
    switch (proto) {
        .ICMP =>  {
            const ty:icmp.ICMPType = @enumFromInt(hdr.type);
            switch (ty) {
                .ECHO_REQ => {
                    const eh:*icmp.ICMPEcho = @ptrCast(hdr);
                    const rp = rawPriv(sk);
                    const id = @byteSwap(eh.id);
                    rp.priv = @ptrFromInt(id);
                    icmp.addIcmpSk(id, sk) catch {
                        //console.print("icmp echo sock already exists, id: {}\n", .{id});
                    };
                }, 
                else => {
                    console.print("unsupported icmp type: {}\n", .{ty});
                }
            }

        },
        else => {
            console.print("unsupported protocol: {}\n", .{proto});
        }
    }
}

fn send_to(sk:*net.Sock, buf:[]const u8, addr:?*const net.SockAddr) anyerror!usize{
    const l = lock.cli();
    defer lock.sti(l);
    const dst = addr orelse return error.UnknownDestination;
    const pkt = try ip.newPacket(@intCast(buf.len));
    defer pkt.free();
    const iph = pkt.getIpV4Hdr();
    const proto = getProto(sk);
    iph.proto = @intFromEnum(proto); 
    iph.setDstAddr(@byteSwap(dst.addr));
    const payload = pkt.getTransPacket();
    @memcpy(payload, buf);

    // XXX: other proto??
    try addProtoSk(proto, sk, @ptrCast(payload.ptr));
    try ip.ipSend(pkt, null);
    return buf.len;
}
fn send(sk:*net.Sock, buf:[]const u8) anyerror!usize{
    return try send_to(sk, buf, &sk.dst_addr.?);
}
fn recv_from(sk:*net.Sock, buf:[]u8, addr:?*net.SockAddr) anyerror![]u8{
    const l = lock.cli();
    defer lock.sti(l);
    while (true) {
        const p = sk.rq.peek() orelse {
            const t = task.getCurrentTask();
            if (t.signal.signalPending()) {
                return error.InterruptedError;
            }
            task.wait(&sk.rwq);
            continue;
        };
        if (addr) |a| {
            const iph = p.getIpV4Hdr();
            a.addr = iph.src_addr;
        }
        
        const tdata = p.getTransPacket();
        const len = @min(buf.len, tdata.len);
        @memcpy(buf[0..len], tdata[0..len]);
        const h = sk.rq.dequeue();
        h.?.free();
        return buf[0..len];
    }
    return &.{};
}

fn recv(sk:*net.Sock, buf:[]u8) anyerror![]u8{
    return try recv_from(sk, buf, null);
}

fn release(sk:*net.Sock) !void {
    const l = lock.cli();
    defer lock.sti(l);
    _=&sk;
    const rp = rawPriv(sk);
    // XXX: other proto?
    if (rp.priv) |p| {
        const id:u16 = @truncate(@intFromPtr(p));
        _=icmp.removeIcmpSk(id);
    }
    alloc.destroy(sk);
    alloc.destroy(rp);
}

pub fn init() void {
    net.registerProtoFamily(.SOCK_RAW, &raw_prot) catch unreachable;

}
