const mem = @import("../mem.zig");
const alloc = mem.allocator;
const task = @import("../task.zig");
const std = @import("std");
const syscall = @import("../syscall.zig");
const fs = @import("../fs.zig");

const SockMap = std.AutoHashMap(Proto, *const ProtoFamily);
var sock_map:SockMap = undefined;

pub const Sock = struct {
    priv:?*anyopaque = null,
    opts:u64 = 0,
    rq:PacketQueue = .{},
    wq:PacketQueue = .{},
    rwq:task.WaitQueue = .{},
    wwq:task.WaitQueue = .{},
    pwl:fs.PollWaitList = .{},
    src_addr:?SockAddr = null,
    dst_addr:?SockAddr = null,
    ops:*const SockOps = undefined,
};

pub const Proto = enum (u8) {
    SOCK_STREAM = 1,
    SOCK_DGRAM = 2,
    SOCK_RAW = 3,
};

pub const SockAddr = extern struct {
    family:u16 = 0,
    port:u16 = 0,
    addr:u32 = 0,
    pad:[8]u8 = [_]u8{0}**8,
};

pub const SockAddrPair = struct {
    src:SockAddr = .{},
    dst:SockAddr = .{}
};

pub const NetDev = struct {
    priv:?*anyopaque = null,
    mac:u48 = 0,
    ipv4_addr:u32 = 0,
    op:*const NetDevOps,
};

pub const NetDevOps = struct {
    read:*const fn(dev:*NetDev) anyerror!?*Packet,
    write:*const fn(dev:*NetDev, pkt:*Packet) anyerror!void,
};

pub var net_dev:*NetDev = undefined;

pub const MsgHdr = extern struct {
    addr:?*SockAddr,
    a_len:u32,
    msg:?[*]fs.IoVec,
    m_len:usize,
    c_msg:?*anyopaque = null,
    c_len:usize,
    flags:u32,
};

//const packets:PacketQueue = .{};
pub const PacketQueue = struct {
    head:?*Packet = null,
    tail:?*Packet = null,
    read_pos:usize = 0,
    count:u32 = 0,
    pub fn getCount(self:*@This()) u32 {
        return self.count;
    }

    pub fn enqueue(self:*@This(), p:*Packet) void {
        p.next = null;
        if (self.tail) |t| {
            t.next = p;
        } else {
            std.debug.assert(self.head == null);
            self.head = p;
        }
        self.tail = p;
        self.count += 1;
    }
    pub fn peek(self:*@This()) ?*Packet {
        return self.head orelse return null;
    }

    pub fn dequeue(self:*@This()) ?*Packet {
        const h = self.head orelse return null;
        self.head = h.next;
        if (self.head == null) self.tail = null;
        self.count -= 1;
        h.next = null;
        return h;
    }
};

pub const ProtoFamily = struct {
    new_sock:*const fn(proto:u32) anyerror!*Sock,
    
};
pub const SockOps = struct {
    bind:*const fn(sk:*Sock, addr:*const SockAddr) anyerror!void,
    listen:*const fn(sk:*Sock) anyerror!void,
    accept:*const fn(sk:*Sock) anyerror!*Sock,
    connect:*const fn(sk:*Sock, addr:*const SockAddr) anyerror!void,
    send_to:*const fn(sk:*Sock, buf:[]const u8, addr:?*const SockAddr) anyerror!usize,
    send:*const fn(sk:*Sock, buf:[]const u8) anyerror!usize,
    recv_from:*const fn(sk:*Sock, buf:[]u8, addr:?*SockAddr) anyerror![]u8,
    recv:*const fn(sk:*Sock, buf:[]u8) anyerror![]u8,
    release:*const fn(sk:*Sock) anyerror!void,
    poll:*const fn(sk:*Sock, pw:fs.PollWait) anyerror!fs.PollResult,
};

pub const TransProto = enum (u8) {
    ICMP = 1,
    IGMP = 2,
    TCP = 6,
    UDP = 17,
    _,
};

pub const NetProto = enum(u16) {
    IPV4 = 0x0800,
    ARP = 0x0806,
    WOL=0x0842	,//Wake-on-LAN
    TRIL=0x22F3	,//TRILL
    DEC=0x6003	,//DECnet Phase IV
    RARP=0x8035	,//RARP
    EAPT=0x809B	,//AppleTalk (EtherTalk)
    AAPT=0x80F3	,//AppleTalk ARP (AARP)
    VLAN=0x8100	,//VLAN-tagged frame (IEEE 802.1Q)
    IPX=0x8137	,//IPX
    SNMP=0x814C	,//SNMP over Ethernet
    IPV6=0x86DD	,//IPv6
    EFC=0x8808	,//Ethernet Flow Control (PAUSE)
    LAC=0x8809	,//Link Aggregation Control Protocol (LACP)
    MPLSU=0x8847	,//MPLS unicast
    MPLSM=0x8848	,//MPLS multicast
    PPPOED=0x8863	,//PPPoE Discovery
    PPPOES=0x8864	,//PPPoE Session
    PB=0x88A8	,//Provider Bridging (Q-in-Q)
    LLDP=0x88CC	,//LLDP
    MS=0x88E5	,//MAC Security (MACsec)
    FCOE=0x8906	,//Fibre Channel over Ethernet (FCoE)
    FIP=0x8914	,//FCoE Initialization Protocol
    HSIP=0x892F	,//HSIP
    HIP=0x894F	,//HIP (Host Identity Protocol)
    LOOP=0x9000	,//Loopback
};

pub const IpV4Hdr = extern struct {
    ver_ihl:u8 align(1) = 0x45,
    dscp_enc:u8 align(1) = 0,
    total_len:u16 align(1) = 0,
    id:u16 align(1) = 0,
    flags_frag_off:u16 align(1) = 0x0040,
    ttl:u8 align(1) = 64,
    proto:u8 align(1),
    csum:u16 align(1) = 0,
    src_addr:u32 align(1) = 0,
    dst_addr:u32 align(1) = 0,
    pub fn getVerion(self:*@This()) u8 {
        return self.ver_ihl >> 4;
    }
    
    pub fn getIHL(self:*@This()) u8 {
        return (self.ver_ihl & 0xf) * 4;
    }

    pub fn getTotalLen(self:*const @This()) u16 {
        return @byteSwap(self.total_len); 
    }

    pub fn getID(self:*@This()) u16 {
        return @byteSwap(self.id);
    }

    pub fn getFlags(self:*@This()) u3 {
        return @truncate(self.flags_frag_off >> 5);
    }

    pub fn getFragOff(self:*@This()) u13 {
        return @truncate((self.flags_frag_off & 0b11111) << 8 | self.flags_frag_off >> 8);
    }

    pub fn getCSum(self:*@This()) u16 {
        return @byteSwap(self.csum);
    }

    pub fn getSrcAddr(self:*@This()) u32 {
        return @byteSwap(self.src_addr);
    }

    pub fn getDstAddr(self:*@This()) u32 {
        return @byteSwap(self.dst_addr);
    }

    pub fn setSrcAddr(self:*@This(), addr:u32) void {
        self.src_addr = @byteSwap(addr);
    }

    pub fn setDstAddr(self:*@This(), addr:u32) void {
        self.dst_addr = @byteSwap(addr);
    }
    pub fn setTotalLen(self:*@This(), len:u16) void {
        self.total_len = @byteSwap(len);
    }
    pub fn setSum(self:*@This(), sum:u16) void {
        self.csum = @byteSwap(sum);
    }
    pub fn setIHL(self:*@This(), ihl:u8) void {
        self.ver_ihl = (self.ver_ihl & ~@as(u8, 0xf)) | ((ihl)/4 & 0xf);
    }
};

pub const NetReceiver = struct {
    ctx:?*anyopaque = null,
    recv:*const fn(nr:*NetReceiver, pkt:*Packet) anyerror!void,
};

const ProtoMap = std.AutoHashMap(NetProto, *NetReceiver);
var proto_map:ProtoMap = undefined;

const eth_off = 0;
const eh_size = 6+6+2;
const net_off = eth_off + eh_size;

pub const Packet = extern struct {
    next:?*Packet align(1) = null,
    len:usize align(1) = 0,
    pub fn new(len:u32) !* Packet {
        const buf = try alloc.alloc(u8, len + @sizeOf(@This()));
        @memset(buf, 0);
        const p:*Packet = @ptrCast(buf.ptr); 
        p.next = null;
        p.len = len;
        return p;
    }

    pub fn free(self:*@This()) void {
        const len = self.len + @sizeOf(@This());
        const ptr:[*]u8 = @ptrCast(self);
        const buf = ptr[0..len];
        alloc.free(buf);
    }

    pub fn getRaw(self:*@This()) []u8 {
        var p:[*]u8 = @ptrCast(self);
        p += @sizeOf(@This());
        return p[0..self.len];
    }
    
    pub fn getNetPacket(self:*@This()) []u8 {
        return self.getRaw()[net_off..];
    }

    pub fn getIpV4Hdr(self:*@This()) *IpV4Hdr {
        const ip = self.getNetPacket();
        return @ptrCast(ip.ptr);
    }

    pub fn getTransPacket(self:*@This()) []u8 {
        const p = self.getNetPacket();
        const iph = self.getIpV4Hdr();
        const pt:[*]u8 = @ptrCast(p.ptr);
        const ihl = iph.getIHL();
        const tlen = iph.getTotalLen();
        return (pt + ihl)[0..tlen - ihl];
    }
    
    pub fn getNetProto(self:*@This()) NetProto {
        const p = self.getRaw(); 
        const pt:*align(1) u16  = @ptrCast(&p[6+6]);
        return @enumFromInt(@byteSwap(pt.*));
    }

    pub fn setNetProto(self:*@This(), proto:NetProto) void {
        self.set(12, @as(u16, @intFromEnum(proto)));
    }

    pub fn setSrcMac(self:*@This(), mac:u48) void {
        self.set(6, mac);
    }

    
    pub fn get(self:*@This(), off:usize, tp:type) tp {
        const p = self.getRaw(); 
        const pt:*align(1) tp = @ptrCast(&p[off]);
        return @byteSwap(pt.*);
    }

    pub fn set(self:*@This(), off:usize, val:anytype) void {
        const v = @byteSwap(val);
        const p = self.getRaw(); 
        const pt:*align(1) @TypeOf(val)  = @ptrCast(&p[off]);
        pt.* = v;
    }

    pub fn setDstMac(self:*@This(), mac:u48) void {
        self.set(0, mac);
    }

    pub fn getDstMac(self:*@This()) u48 {
        return self.get(0, u48);
    }
};

const console = @import("../console.zig");
pub var net_rcv_wq:task.WaitQueue = .{};
const lock = @import("../lock.zig");
pub fn registerNetDev(dev:*NetDev) void {
    net_dev = dev;
}

pub fn registerProtoFamily(p: Proto, nf:*const ProtoFamily) !void {
    try sock_map.put(p, nf);
}

fn receive_pkt(a:?*anyopaque) u16 {
    _=&a;
    while (true) {
        const p = blk:{
            const l = lock.cli();
            defer lock.sti(l);
            const p = net_dev.op.read(net_dev) catch |e| {
                console.print("error receiving packets: {}\n", .{e});
                task.scheduleWithIF();
                continue;
            } orelse {
                task.wait(&net_rcv_wq);
                continue;
            };
            break :blk p;
        };
        const r = proto_map.get(p.getNetProto()) orelse {
            console.print("unknown network protocol: 0x{x}", .{@intFromEnum(p.getNetProto())});
            printPacket(p);
            p.free();
            continue;
        };
        r.recv(r, p) catch |e| {
            console.print("error receiving packet, error:{}", .{e});
            // p was already freed!!
            //printPacket(p);
        };
    }
}

fn printPacket(p:* align(1) Packet) void {
    console.print("|{s}|", .{std.fmt.fmtSliceHexLower(p.getRaw())});
}

pub fn newPacket(payload_len: u32) !*Packet {
    return try Packet.new(eh_size + payload_len);
}

pub fn xmitPacket(pkt:*Packet) !void {
    try net_dev.op.write(net_dev, pkt);
}

pub fn registerNetProtoHandler(proto:NetProto, h:*const NetReceiver) !void {
    try proto_map.put(proto, @constCast(h));
}

const kthread = @import("../kthread.zig");
pub fn init() void {
    proto_map = ProtoMap.init(alloc);
    sock_map = SockMap.init(alloc);

    kthread.createKThread("pkt_rcv", &receive_pkt, null);
    
    syscall.registerSysCall(syscall.SysCallNo.sys_socket, &sysSocket);
    syscall.registerSysCall(syscall.SysCallNo.sys_bind, &sysBind);
    syscall.registerSysCall(syscall.SysCallNo.sys_listen, &sysListen);
    syscall.registerSysCall(syscall.SysCallNo.sys_accept, &sysAccept);
    syscall.registerSysCall(syscall.SysCallNo.sys_connect, &sysConnect);
    syscall.registerSysCall(syscall.SysCallNo.sys_recvfrom, &sysRecvFrom);
    syscall.registerSysCall(syscall.SysCallNo.sys_sendto, &sysSendTo);
    syscall.registerSysCall(syscall.SysCallNo.sys_setsockopt, &sysSetSockOpt);
    syscall.registerSysCall(syscall.SysCallNo.sys_getsockname, &sysGetSockName);
    syscall.registerSysCall(syscall.SysCallNo.sys_recvmsg, &sysRecvMsg);

}

pub fn sockPoll(sk:*Sock, pw:fs.PollWait) anyerror!fs.PollResult {
    if (pw.events == 0) return error.NoEventsToPoll;
    const l = lock.cli();
    defer lock.sti(l);
    var r:u16 = 0;
    if ((pw.events & fs.PollIn) > 0 and sk.rq.getCount() > 0) {
        r |= fs.PollIn; 
    }
    if ((pw.events & fs.PollOut) > 0) {
        r |= fs.PollOut;
    }
    if (r == 0) { // added only if no event yet, sync with release!!
        sk.pwl.events = pw.events;
        sk.pwl.wq.append(pw.wqn);
    }
    return fs.PollResult{.wqn = pw.wqn, .events = r, .priv = sk, .release = &releasePollResult};
}

fn releasePollResult(pr:fs.PollResult) void {
    const sk:*Sock = @alignCast(@ptrCast(pr.priv.?)); 
    if (pr.events > 0) return; // wait queue was only added if events == 0
    const l = lock.cli();
    defer lock.sti(l);
    sk.pwl.wq.remove(pr.wqn);
}

const sk_fops:fs.FileOps = .{.read = &read, 
    .write = &write, 
    .poll = &poll,
    .close = &close,
    .finalize = &fs.close,

};

fn poll(file:*fs.File, pw:fs.PollWait) !fs.PollResult {
    const sk:*Sock = @alignCast(@ptrCast(file.ctx.?));
    return try sk.ops.poll(sk, pw);
}

pub fn notifyWaiters(sk:*Sock, events:u16) void {
    if (events & fs.PollIn > 0) {
        task.wakeup(&sk.rwq);
    }
    if (events & fs.PollOut > 0) {
        task.wakeup(&sk.wwq);
    }
    if (events & sk.pwl.events > 0) {
        task.wakeup(&sk.pwl.wq);
    }
}

fn read(file:*fs.File, buf:[]u8) anyerror![]u8 {
    const sk:*Sock = @alignCast(@ptrCast(file.ctx.?));
    return try sk.ops.recv(sk, buf);
}
fn write(file:*fs.File, buf:[]const u8) anyerror!usize {
    const sk:*Sock = @alignCast(@ptrCast(file.ctx.?));
    return try sk.ops.send(sk, buf);
}
    // called right before *File is freed
fn close(file:*fs.File) anyerror!void {
    const sk:*Sock = @alignCast(@ptrCast(file.ctx.?));
    try sk.ops.release(sk);
}

pub export fn sysSetSockOpt(fd:u32, level:u32, name:u32, val:?[*]u8, len:u32) callconv(std.builtin.CallingConvention.SysV) i64 {
    _=&fd;
    _=&level;
    _=&name;
    _=&val;
    _=&len;
    return 0;
}

pub export fn sysSocket(family:u32, ptype:u32, proto:u32) callconv(std.builtin.CallingConvention.SysV) i64 {
    _=&family;
    _=&proto;
    const l = lock.cli();
    defer lock.sti(l);
    const pt:u8 = @truncate(ptype);
    const t = task.getCurrentTask();
    const fd = t.fs.getFreeFd() catch return -1;
    const nf = sock_map.get(@enumFromInt(pt)) orelse return -1;
    const sk = nf.new_sock(proto) catch return -1;
    sk.opts = ptype & ~@as(u32, 0xff);
    const file = fs.File.get_new_ex(&sk_fops) catch {
        sk.ops.release(sk) catch return -1;
        return -1;
    };
    file.ctx = sk;
    t.fs.installFd(fd, file);
    return @intCast(fd);
}

pub export fn sysGetSockName(fd:u32, addr:?*SockAddr, _:u32) callconv(std.builtin.CallingConvention.SysV) i64 {
    mem.checkUserAddr(addr) catch return -1;
    const a = addr.?;
    const t = task.getCurrentTask();
    const f = t.fs.getFile(fd) orelse return -1;
    const sk:*Sock = @alignCast(@ptrCast(f.ctx.?));
    const sa = sk.src_addr orelse return -1;
    a.* = .{
        .family = 2, // ipv4 only
        .addr = @byteSwap(sa.addr),
        .port = @byteSwap(sa.port),
    };
    return 0;
}

pub export fn sysBind(fd:u32, addr:*const SockAddr, _:u32) callconv(std.builtin.CallingConvention.SysV) i64 {
    const t = task.getCurrentTask();
    const f = t.fs.getFile(fd) orelse return -1;
    const sk:*Sock = @alignCast(@ptrCast(f.ctx.?));
    sk.ops.bind(sk, addr) catch return -1;
    return 0;
}

pub export fn sysListen(fd:u32, _:u32) callconv(std.builtin.CallingConvention.SysV) i64 {
    const t = task.getCurrentTask();
    const f = t.fs.getFile(fd) orelse return -1;
    const sk:*Sock = @alignCast(@ptrCast(f.ctx.?));
    sk.ops.listen(sk) catch return -1;
    return 0;
}

fn doAccept(fd:u32, addr:?*SockAddr, _:u32) !i64 {
    const t = task.getCurrentTask();
    const f = t.fs.getFile(fd) orelse return -1;
    const sk:*Sock = @alignCast(@ptrCast(f.ctx.?));
    const new = try sk.ops.accept(sk);
    errdefer new.ops.release(new) catch {};
    const l = lock.cli();
    defer lock.sti(l);
    const nfd = try t.fs.getFreeFd();
    const file = try fs.File.get_new_ex(&sk_fops);
    file.ctx = new;
    t.fs.installFd(nfd, file);
    if (addr) |a| {
        if (new.dst_addr) |d| {
            a.addr = @byteSwap(d.addr);
            a.port = @byteSwap(d.port);
        }
    }
    return @intCast(nfd);

}

pub export fn sysAccept(fd:u32, addr:?*SockAddr, adr_len:u32) callconv(std.builtin.CallingConvention.SysV) i64 {
    return doAccept(fd, addr, adr_len) catch |e| {
        if (e == error.InterruptedError) return -syscall.EAGAIN;
        return -1;
    };
}

pub export fn sysConnect(fd:u32, addr:*const SockAddr, _:u32) callconv(std.builtin.CallingConvention.SysV) i64 {
    const t = task.getCurrentTask();
    const f = t.fs.getFile(fd) orelse return -1;
    const sk:*Sock = @alignCast(@ptrCast(f.ctx.?));
    sk.ops.connect(sk, addr) catch return -1;
    return 0;
}

pub export fn sysSend(fd:u32, buf:[*]u8, len:usize, _:u32) callconv(std.builtin.CallingConvention.SysV) i64 {
    const t = task.getCurrentTask();
    const f = t.fs.getFile(fd) orelse return -1;
    const r = write(f, buf[0..len]) catch return -1;
    return @intCast(r);
}

pub export fn sysRecv(fd:u32, buf:[*]u8, len:usize, _:u32) callconv(std.builtin.CallingConvention.SysV) i64 {
    const l = lock.cli();
    defer lock.sti(l);
    const t = task.getCurrentTask();
    const f = t.fs.getFile(fd) orelse return -1;
    const r = (read(f, buf[0..len]) catch |e| {
        return -@as(i64, @intFromError(e));
    }).len;
    return @intCast(r);
}

pub export fn sysSendTo(fd:u32, buf:[*]u8, len:usize, _:u32, addr:?*const SockAddr, _:u32)
    callconv(std.builtin.CallingConvention.SysV) i64 {
    const t = task.getCurrentTask();
    const f = t.fs.getFile(fd) orelse return -1;
    const sk:*Sock = @alignCast(@ptrCast(f.ctx.?));
    const r = sk.ops.send_to(sk, buf[0..len], addr) catch return -1;
    return @intCast(r);
}

pub export fn sysRecvFrom(fd:u32, buf:[*]u8,
    len:usize, _:u32, addr:?*SockAddr, flags:u32) callconv(std.builtin.CallingConvention.SysV) i64 {
    _=&flags;
    const l = lock.cli();
    defer lock.sti(l);
    const t = task.getCurrentTask();
    const f = t.fs.getFile(fd) orelse return -1;
    const sk:*Sock = @alignCast(@ptrCast(f.ctx.?));
    const r = (sk.ops.recv_from(sk, buf[0..len], addr) catch |e| { 
        if (e == error.InterruptedError) {
            return -syscall.EINTR;
        }
        return -1;

    }).len;
    return @intCast(r);
}

pub export fn sysRecvMsg(fd:u32, msg:?*MsgHdr, flags:u32) callconv(std.builtin.CallingConvention.SysV) i64 {
    _=&flags;
    const m = msg orelse return -1;
    const v = m.msg orelse return 0;
    const l = lock.cli();
    defer lock.sti(l);
    const t = task.getCurrentTask();
    const f = t.fs.getFile(fd) orelse return -1;
    const sk:*Sock = @alignCast(@ptrCast(f.ctx.?));
    var ret:i64 = 0;
    outer: for (0..m.m_len) |i| {
        const vc = v[i];
        var off:usize = 0;
        const vb = vc.iov_base orelse continue;
        while (true) {
            var node = task.WaitQueue.Node{.data = t};
            const pw = fs.PollWait{.events = fs.PollIn, .wqn = &node};
            const pr = sk.ops.poll(sk, pw) catch |e| {
                if (ret > 0) return ret;
                return -@as(i64, @intFromError(e));
            };
            defer pr.release(pr);
            if (pr.events == 0) break :outer;
            const r = (sk.ops.recv_from(sk, vb[off..vc.iov_len], m.addr) catch |e| { 
                if (ret > 0) return ret;
                return -@as(i64, @intFromError(e));
            }).len;
            off += r;
            ret += @intCast(r);
            if (off >= vc.iov_len) {
                break;
            }

        }
    }
    return @intCast(ret);
}

