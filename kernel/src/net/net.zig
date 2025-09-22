const alloc = @import("../mem.zig").allocator;
const task = @import("../task.zig");
const std = @import("std");

// dummy config:
pub const ip_addr = [_]u8{192, 168, 1, 2};

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

//const packets:PacketQueue = .{};
const PacketQueue = struct {
    head:?*Packet = null,
    tail:?*Packet = null,
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
    pub fn dequeue(self:*@This()) ?*Packet {
        const h = self.head orelse return null;
        self.head = h.next;
        if (self.head == null) self.tail = null;
        self.count -= 1;
        h.next = null;
        return h;
    }
};

pub const ProtoSock = struct {
    new_sock:*const fn() anyerror!*Socket,
    send:*const fn(sk:*Socket, buf:[]u8) anyerror!usize,
    recv:*const fn(sk:*Socket, buf:[]u8) anyerror!void,
};

pub const Socket = struct {
    priv:?*anyopaque = null,
    q:PacketQueue = .{},
    wq:task.WaitQueue = .{},

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
        return self.ver_ihl & 0xf;
    }

    pub fn getTotalLen(self:*@This()) u16 {
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
            continue;
        };
        r.recv(r, p) catch {
            console.print("error receiving packet, proto: 0x{x}", .{@intFromEnum(p.getNetProto())});
            printPacket(p);
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

pub fn init() void {
    proto_map = ProtoMap.init(alloc);
    const arg:task.CloneArgs = .{.func = &receive_pkt, .name = "pkt_rcv"};
    _=task.clone(&arg) catch unreachable;
}

